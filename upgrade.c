#define _DEFAULT_SOURCE
#include <alpm.h>
#include <alpm_list.h>
#include <ctype.h>
#include <curl/curl.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <pwd.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/prctl.h>
#include <sys/stat.h>
#include <sys/statvfs.h>
#include <sys/sysinfo.h>
#include <sys/types.h>
#include <sys/utsname.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

// ANSI escape sequences for terminal color output
#define CLR_CYAN "\033[1;36m"
#define CLR_GREEN "\033[1;32m"
#define CLR_YELLOW "\033[1;33m"
#define CLR_RED "\033[1;31m"
#define CLR_MAGENTA "\033[1;35m"
#define CLR_RESET "\033[0m"

// Minimum free disk space (in GiB) required on / and /var/cache/pacman/pkg
#define MIN_FREE_GIB 2.0

// Growable in-memory buffer populated by libcurl's write callback
struct mem_buf {
  char *data;
  size_t size;
};

// Tracks an installed package not found in any configured official sync DB
struct foreign_pkg {
  const char *name;
  const char *ver;
  uint8_t in_aur;      // Set to 1 once confirmed present in AUR RPC results
  uint8_t ignored;     // Set to 1 if matched by IgnorePkg/IgnoreGroup
  uint8_t out_of_date; // Set to 1 if OutOfDate is non-null in AUR RPC
  uint8_t orphaned;    // Set to 1 if AUR RPC reports Maintainer: null
};

// Forks and executes an external command, waiting for it to finish.
// Retries waitpid() if interrupted by a signal (EINTR).
// Returns 0 on exit status 0, -2 if interrupted by SIGINT/SIGTERM, or -1 on
// any other non-zero exit / error.
static int run_cmd(char *const argv[]) {
  // Flush our buffered output first so it stays ordered with the child's
  // output when stdout is a pipe or log file (e.g. `upgrade | tee log`)
  fflush(NULL);
  pid_t pid = fork();
  if (pid < 0) {
    perror("fork");
    return -1;
  }
  if (pid == 0) {
    execvp(argv[0], argv);
    perror(argv[0]);
    _exit(127);
  }
  int status;
  while (waitpid(pid, &status, 0) < 0) {
    if (errno != EINTR)
      return -1;
  }
  if (WIFSIGNALED(status) &&
      (WTERMSIG(status) == SIGINT || WTERMSIG(status) == SIGTERM))
    return -2;
  if (WIFEXITED(status)) {
    if (WEXITSTATUS(status) == 0)
      return 0;
    if (WEXITSTATUS(status) == 128 + SIGINT)
      return -2;
  }
  return -1;
}

// Executes `argv`, capturing stdout into `buf` (null-terminated) while routing
// stderr to /dev/null so diagnostic probes stay quiet when optional daemons or
// user buses are unavailable. Returns bytes captured (>= 0), or -1 on error.
static ssize_t capture_cmd_output(char *const argv[], char *buf, size_t buf_sz,
                                  int *exit_code) {
  if (buf_sz == 0)
    return -1;
  buf[0] = '\0';
  if (exit_code)
    *exit_code = -1;

  int pfd[2];
  if (pipe(pfd) != 0)
    return -1;

  fflush(NULL);
  pid_t pid = fork();
  if (pid < 0) {
    close(pfd[0]);
    close(pfd[1]);
    return -1;
  }
  if (pid == 0) {
    close(pfd[0]);
    dup2(pfd[1], STDOUT_FILENO);
    if (pfd[1] > STDOUT_FILENO)
      close(pfd[1]);
    int devnull = open("/dev/null", O_WRONLY);
    if (devnull >= 0) {
      dup2(devnull, STDERR_FILENO);
      if (devnull > STDERR_FILENO)
        close(devnull);
    }
    execvp(argv[0], argv);
    _exit(127);
  }

  close(pfd[1]);
  size_t total = 0;
  char drain[512];
  for (;;) {
    ssize_t n;
    if (total + 1 < buf_sz)
      n = read(pfd[0], buf + total, buf_sz - 1 - total);
    else
      n = read(pfd[0], drain, sizeof(drain));
    if (n > 0) {
      if (total + 1 < buf_sz)
        total += (size_t)n;
    } else if (n == 0) {
      break;
    } else if (errno != EINTR) {
      break;
    }
  }
  buf[total] = '\0';
  close(pfd[0]);

  int status;
  while (waitpid(pid, &status, 0) < 0) {
    if (errno != EINTR)
      return -1;
  }
  if (exit_code && WIFEXITED(status))
    *exit_code = WEXITSTATUS(status);
  return (ssize_t)total;
}

static void print_indented_lines(const char *text) {
  const char *p = text;
  while (*p != '\0') {
    const char *nl = strchr(p, '\n');
    size_t len = nl ? (size_t)(nl - p) : strlen(p);
    if (len > 0 && p[len - 1] == '\r')
      len--;
    if (len > 0)
      printf("    %.*s\n", (int)len, p);
    if (!nl)
      break;
    p = nl + 1;
  }
}

// libcurl write callback: appends incoming HTTP response chunks into a
// null-terminated mem_buf on the heap.
static size_t write_cb(void *contents, size_t size, size_t nmemb, void *userp) {
  size_t realsize = size * nmemb;
  struct mem_buf *mem = (struct mem_buf *)userp;

  char *ptr = realloc(mem->data, mem->size + realsize + 1);
  if (!ptr)
    return 0;

  mem->data = ptr;
  memcpy(&(mem->data[mem->size]), contents, realsize);
  mem->size += realsize;
  mem->data[mem->size] = '\0';
  return realsize;
}

// Lightweight JSON string extractor for a bounded object slice [start, end).
// Searches for `key` (e.g. "\"Name\":"), skips whitespace, and copies the
// quoted string value into `out` while unescaping backslash sequences.
static int extract_json_str(const char *start, const char *end, const char *key,
                            char *out, size_t out_sz) {
  const char *p = start;
  size_t klen = strlen(key);

  while ((p = strstr(p, key)) != NULL && p < end) {
    p += klen;
    while (p < end && (*p == ' ' || *p == '\t'))
      p++;
    if (p < end && *p == '"') {
      p++;
      size_t i = 0;
      while (p < end && *p != '"' && i + 1 < out_sz) {
        if (*p == '\\' && (p + 1) < end)
          p++;
        out[i++] = *p++;
      }
      out[i] = '\0';
      return 0;
    }
  }
  return -1;
}

// Queries the AUR RPC v5 multi-info endpoint for all foreign packages.
// Requests are sent in batches of 100 package names to stay well below
// AUR's HTTP URI length limit (~8 KB). Compares versions via alpm_pkg_vercmp()
// and flags foreign packages that no longer exist in the AUR.
static size_t audit_aur_packages(CURL *curl, struct foreign_pkg *pkgs,
                                 size_t count) {
  if (count == 0)
    return 0;

  const size_t batch_size = 100;
  // Hard cap on the request URI; a batch is flushed early once the next
  // escaped name would not fit, so no package is ever silently dropped.
  const size_t url_cap = 8000;
  char *url = malloc(url_cap);
  if (!url)
    return 0;

  curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_cb);
  curl_easy_setopt(curl, CURLOPT_USERAGENT, "upgrade-alpm/2.5");
  curl_easy_setopt(curl, CURLOPT_ACCEPT_ENCODING, ""); // Enable gzip/deflate
  curl_easy_setopt(curl, CURLOPT_TIMEOUT, 10L);

  size_t aur_updates = 0;

  for (size_t batch_start = 0; batch_start < count;) {
    size_t batch_end = batch_start;

    // Build the query URL:
    // https://aur.archlinux.org/rpc/v5/info?arg[]=pkg1&arg[]=pkg2...
    const size_t base_len = (size_t)snprintf(
        url, url_cap, "https://aur.archlinux.org/rpc/v5/info?");
    size_t url_len = base_len;

    while (batch_end < count && batch_end - batch_start < batch_size) {
      char *esc = curl_easy_escape(curl, pkgs[batch_end].name, 0);
      if (!esc) {
        batch_end++;
        continue;
      }
      int written = snprintf(url + url_len, url_cap - url_len, "%sarg[]=%s",
                             (url_len == base_len) ? "" : "&", esc);
      curl_free(esc);
      if (written < 0 || url_len + (size_t)written >= url_cap) {
        // Doesn't fit: undo the partial write and send this batch as-is;
        // the package will lead the next batch instead.
        url[url_len] = '\0';
        if (batch_end == batch_start)
          batch_end++; // Pathological single name larger than url_cap
        break;
      }
      url_len += (size_t)written;
      batch_end++;
    }

    struct mem_buf resp = {malloc(1), 0};
    if (!resp.data) {
      free(url);
      return aur_updates;
    }
    resp.data[0] = '\0';

    curl_easy_setopt(curl, CURLOPT_URL, url);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, (void *)&resp);

    CURLcode res = curl_easy_perform(curl);
    if (res != CURLE_OK) {
      fprintf(stderr, CLR_RED ":: AUR RPC error: %s\n" CLR_RESET,
              curl_easy_strerror(res));
      free(resp.data);
      free(url);
      return aur_updates;
    }

    // Bail out if the RPC returned an error object or no "results" array,
    // so we don't falsely report every foreign package as missing from AUR.
    const char *cursor = strstr(resp.data, "\"results\":");
    if (!cursor || strstr(resp.data, "\"type\":\"error\"")) {
      fprintf(stderr, CLR_RED
              ":: AUR RPC returned an invalid or error response.\n" CLR_RESET);
      free(resp.data);
      free(url);
      return aur_updates;
    }

    // Walk the "results" array by tracking brace depth outside of JSON strings.
    // Each top-level '{ ... }' block inside "results" is one AUR package
    // object.
    const char *obj_start = NULL;
    int depth = 0;
    int in_str = 0;

    for (const char *p = cursor; *p != '\0'; p++) {
      if (in_str) {
        if (*p == '\\' && *(p + 1) != '\0')
          p++; // Skip escaped character (e.g. \\ or \") inside string
        else if (*p == '"')
          in_str = 0;
        continue;
      }
      if (*p == '"') {
        in_str = 1;
        continue;
      }

      if (*p == '{') {
        if (depth == 0)
          obj_start = p;
        depth++;
      } else if (*p == '}') {
        depth--;
        if (depth == 0 && obj_start) {
          char pkg_name[128], aur_ver[128];
          if (extract_json_str(obj_start, p, "\"Name\":", pkg_name,
                               sizeof(pkg_name)) == 0 &&
              extract_json_str(obj_start, p, "\"Version\":", aur_ver,
                               sizeof(aur_ver)) == 0) {

            const char *ood = strstr(obj_start, "\"OutOfDate\":");
            int is_ood = 0;
            if (ood && ood < p) {
              ood += 12;
              while (ood < p && (*ood == ' ' || *ood == '\t'))
                ood++;
              if (ood < p && isdigit((unsigned char)*ood))
                is_ood = 1;
            }

            // AUR uses a JSON null Maintainer field for orphaned packages.
            const char *maint = strstr(obj_start, "\"Maintainer\"");
            int is_orphaned = 0;
            if (maint && maint < p) {
              maint += strlen("\"Maintainer\"");
              while (maint < p && (*maint == ' ' || *maint == '\t' ||
                                   *maint == '\r' || *maint == '\n'))
                maint++;
              if (maint < p && *maint == ':') {
                maint++;
                while (maint < p && (*maint == ' ' || *maint == '\t' ||
                                     *maint == '\r' || *maint == '\n'))
                  maint++;
                if (maint + 4 <= p && strncmp(maint, "null", 4) == 0 &&
                    (maint + 4 == p || !isalnum((unsigned char)maint[4])))
                  is_orphaned = 1;
              }
            }

            for (size_t i = batch_start; i < batch_end; i++) {
              if (strcmp(pkgs[i].name, pkg_name) == 0) {
                pkgs[i].in_aur = 1;
                pkgs[i].out_of_date = (uint8_t)is_ood;
                pkgs[i].orphaned = (uint8_t)is_orphaned;
                if (!pkgs[i].ignored &&
                    alpm_pkg_vercmp(aur_ver, pkgs[i].ver) > 0) {
                  if (aur_updates == 0) {
                    printf(CLR_YELLOW "\n[!] Pending AUR Updates:\n" CLR_RESET);
                  }
                  printf("    %-28s %s -> " CLR_GREEN "%s" CLR_RESET "\n",
                         pkg_name, pkgs[i].ver, aur_ver);
                  aur_updates++;
                }
                break;
              }
            }
          }
          obj_start = NULL;
        }
      }
    }

    free(resp.data);
    batch_start = batch_end;
  }

  free(url);

  // Report installed AUR packages flagged out-of-date upstream
  size_t flagged_ood = 0;
  for (size_t i = 0; i < count; i++) {
    if (pkgs[i].in_aur && pkgs[i].out_of_date) {
      if (flagged_ood == 0) {
        printf(CLR_YELLOW "\n[!] Flagged Out-of-Date AUR Packages:" CLR_RESET);
      }
      printf(" %s", pkgs[i].name);
      flagged_ood++;
    }
  }
  if (flagged_ood > 0)
    printf("\n");

  // AUR packages with no maintainer can remain unpatched until someone adopts
  // them. This is a maintenance warning, not proof that the package is unsafe.
  size_t orphaned_aur = 0;
  for (size_t i = 0; i < count; i++) {
    if (pkgs[i].in_aur && pkgs[i].orphaned) {
      if (orphaned_aur == 0) {
        printf(CLR_YELLOW "\n[!] Orphaned AUR Packages (no maintainer):\n"
                         CLR_RESET);
      }
      printf("    - %-28s (%s)\n", pkgs[i].name, pkgs[i].ver);
      orphaned_aur++;
    }
  }

  // Any foreign package still marked in_aur == 0 was not returned by AUR RPC
  size_t unmaintained = 0;
  for (size_t i = 0; i < count; i++) {
    if (!pkgs[i].in_aur) {
      if (unmaintained == 0) {
        printf(CLR_MAGENTA "\n[?] Foreign packages NOT in AUR (dropped, "
                           "-debug, or local build):\n" CLR_RESET);
      }
      printf("    - %-28s (%s)\n", pkgs[i].name, pkgs[i].ver);
      unmaintained++;
    }
  }

  return aur_updates;
}

// Reads the tail of /var/log/pacman.log to find the UTC timestamp of the most
// recent upgrade/install transaction, or 0 if unavailable.
static time_t last_pacman_upgrade_time(void) {
  FILE *fp = fopen("/var/log/pacman.log", "r");
  if (!fp)
    return 0;

  if (fseek(fp, 0, SEEK_END) == 0) {
    long end = ftell(fp);
    if (end > 262144) {
      fseek(fp, end - 262144, SEEK_SET);
      char discard[512];
      if (!fgets(discard, sizeof(discard), fp)) {
        fclose(fp);
        return 0;
      }
    } else {
      rewind(fp);
    }
  }

  time_t last = 0;
  char line[1024];
  while (fgets(line, sizeof(line), fp)) {
    if (line[0] != '[')
      continue;
    if (!strstr(line, "[PACMAN] starting full system upgrade") &&
        !strstr(line, "[ALPM] upgraded ") && !strstr(line, "[ALPM] installed "))
      continue;

    int y, mo, d, H, M, S, tzh, tzm;
    char tzs;
    if (sscanf(line, "[%d-%d-%dT%d:%d:%d%c%2d%2d]", &y, &mo, &d, &H, &M, &S,
               &tzs, &tzh, &tzm) == 9) {
      struct tm tm;
      memset(&tm, 0, sizeof(tm));
      tm.tm_year = y - 1900;
      tm.tm_mon = mo - 1;
      tm.tm_mday = d;
      tm.tm_hour = H;
      tm.tm_min = M;
      tm.tm_sec = S;
      time_t t = timegm(&tm);
      if (t != (time_t)-1) {
        long off = (long)tzh * 3600L + (long)tzm * 60L;
        last = (tzs == '-') ? (t + off) : (t - off);
      }
    }
  }
  fclose(fp);
  return last;
}

// Locale-independent parser for RSS RFC-2822 dates, e.g.:
// "Wed, 21 Oct 2026 13:58:42 +0000"
static time_t parse_rfc2822_date(const char *s) {
  static const char *const months[12] = {"Jan", "Feb", "Mar", "Apr",
                                         "May", "Jun", "Jul", "Aug",
                                         "Sep", "Oct", "Nov", "Dec"};
  const char *comma = strchr(s, ',');
  if (comma)
    s = comma + 1;

  int d, y, H, M, S, tzh = 0, tzm = 0;
  char mon[4] = "", tzs = '+';
  int n = sscanf(s, " %d %3s %d %d:%d:%d %c%2d%2d", &d, mon, &y, &H, &M, &S,
                 &tzs, &tzh, &tzm);
  if (n < 6)
    return 0;

  int mi = -1;
  for (int i = 0; i < 12; i++) {
    if (strncmp(mon, months[i], 3) == 0) {
      mi = i;
      break;
    }
  }
  if (mi < 0)
    return 0;

  struct tm tm;
  memset(&tm, 0, sizeof(tm));
  tm.tm_year = y - 1900;
  tm.tm_mon = mi;
  tm.tm_mday = d;
  tm.tm_hour = H;
  tm.tm_min = M;
  tm.tm_sec = S;
  time_t t = timegm(&tm);
  if (t == (time_t)-1)
    return 0;
  long off = (long)tzh * 3600L + (long)tzm * 60L;
  return (tzs == '-') ? (t + off) : (t - off);
}

// Extracts text between `open_tag` and `close_tag` inside [start, end),
// decoding basic XML character entities in place.
static int extract_xml_tag(const char *start, const char *end,
                           const char *open_tag, const char *close_tag,
                           char *out, size_t out_sz) {
  const char *a = strstr(start, open_tag);
  if (!a || a >= end)
    return -1;
  a += strlen(open_tag);
  const char *b = strstr(a, close_tag);
  if (!b || b > end)
    return -1;

  size_t i = 0;
  while (a < b && i + 1 < out_sz) {
    if (*a == '&') {
      if (strncmp(a, "&amp;", 5) == 0) {
        out[i++] = '&';
        a += 5;
        continue;
      } else if (strncmp(a, "&lt;", 4) == 0) {
        out[i++] = '<';
        a += 4;
        continue;
      } else if (strncmp(a, "&gt;", 4) == 0) {
        out[i++] = '>';
        a += 4;
        continue;
      } else if (strncmp(a, "&quot;", 6) == 0) {
        out[i++] = '"';
        a += 6;
        continue;
      } else if (strncmp(a, "&#39;", 5) == 0 || strncmp(a, "&apos;", 6) == 0) {
        out[i++] = '\'';
        a += (a[1] == '#') ? 5 : 6;
        continue;
      }
    }
    out[i++] = *a++;
  }
  out[i] = '\0';
  return 0;
}

// Fetches the official Arch Linux News RSS feed and highlights any advisories
// published since the system's last pacman upgrade (or within the last 14 days
// if /var/log/pacman.log has no prior timestamp).
static void check_arch_news(CURL *curl) {
  time_t cutoff = last_pacman_upgrade_time();
  if (cutoff <= 0)
    cutoff = time(NULL) - 14 * 86400;

  struct mem_buf resp = {malloc(1), 0};
  if (!resp.data)
    return;
  resp.data[0] = '\0';

  curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_cb);
  curl_easy_setopt(curl, CURLOPT_USERAGENT, "upgrade-alpm/2.5");
  curl_easy_setopt(curl, CURLOPT_ACCEPT_ENCODING, "");
  curl_easy_setopt(curl, CURLOPT_TIMEOUT, 6L);
  curl_easy_setopt(curl, CURLOPT_URL, "https://archlinux.org/feeds/news/");
  curl_easy_setopt(curl, CURLOPT_WRITEDATA, (void *)&resp);

  if (curl_easy_perform(curl) != CURLE_OK) {
    free(resp.data);
    return; // Non-fatal if archlinux.org is unreachable
  }

  size_t fresh_news = 0;
  const char *p = resp.data;
  while ((p = strstr(p, "<item>")) != NULL) {
    const char *item_end = strstr(p, "</item>");
    if (!item_end)
      break;

    char title[256], link[256], pub[64];
    if (extract_xml_tag(p, item_end, "<title>", "</title>", title,
                        sizeof(title)) == 0 &&
        extract_xml_tag(p, item_end, "<link>", "</link>", link, sizeof(link)) ==
            0 &&
        extract_xml_tag(p, item_end, "<pubDate>", "</pubDate>", pub,
                        sizeof(pub)) == 0) {
      time_t pub_t = parse_rfc2822_date(pub);
      if (pub_t > cutoff) {
        if (fresh_news == 0) {
          printf(CLR_YELLOW
                 "\n[!] Arch Linux News since your last upgrade:\n" CLR_RESET);
        }
        printf("    - %s\n      %s\n", title, link);
        fresh_news++;
      }
    }
    p = item_end + 7;
  }

  if (fresh_news == 0) {
    printf(CLR_GREEN
           "[✓] Arch Linux News: no new advisories since last upgrade.\n"
           CLR_RESET);
  }
  free(resp.data);
}

// Returns the trimmed value of a "Key = Value" config line (modified in
// place), or NULL if the line has no '=' or an empty value.
static char *conf_value(char *line) {
  char *v = strchr(line, '=');
  if (!v)
    return NULL;
  v++;
  while (*v == ' ' || *v == '\t')
    v++;
  v[strcspn(v, "\r\n")] = '\0';
  size_t n = strlen(v);
  while (n > 0 && (v[n - 1] == ' ' || v[n - 1] == '\t'))
    v[--n] = '\0';
  return (*v != '\0') ? v : NULL;
}

// Expands pacman's $repo / $arch placeholders in a Server URL template and
// registers the result as a mirror for `db`. Over-long URLs are skipped.
static void add_repo_server(alpm_db_t *db, const char *tmpl, const char *arch) {
  const char *repo = alpm_db_get_name(db);
  char url[1024];
  size_t o = 0;
  const char *s = tmpl;

  while (*s != '\0' && o + 1 < sizeof(url)) {
    const char *sub = NULL;
    if (strncmp(s, "$repo", 5) == 0)
      sub = repo;
    else if (strncmp(s, "$arch", 5) == 0)
      sub = arch;

    if (sub) {
      size_t n = strlen(sub);
      if (o + n >= sizeof(url))
        return;
      memcpy(url + o, sub, n);
      o += n;
      s += 5;
    } else {
      url[o++] = *s++;
    }
  }
  if (*s != '\0')
    return; // Truncated
  url[o] = '\0';
  alpm_db_add_server(db, url);
}

// Reads `Server = ...` lines from an Include'd mirrorlist into `db`
static void add_servers_from_include(alpm_db_t *db, const char *path,
                                     const char *arch) {
  FILE *fp = fopen(path, "r");
  if (!fp)
    return;

  char line[1024];
  while (fgets(line, sizeof(line), fp)) {
    char *p = line;
    while (*p == ' ' || *p == '\t')
      p++;
    if (strncmp(p, "Server", 6) == 0) {
      char *v = conf_value(p);
      if (v)
        add_repo_server(db, v, arch);
    }
  }
  fclose(fp);
}

// Dynamically parses /etc/pacman.conf to register all configured repositories
// into libalpm
static void register_pacman_repos(alpm_handle_t *handle) {
  FILE *fp = fopen("/etc/pacman.conf", "r");
  if (!fp) {
    // Fallback defaults if config unreadable
    const char *fallback[] = {"core", "extra", "multilib"};
    for (size_t i = 0; i < 3; i++)
      alpm_register_syncdb(handle, fallback[i], ALPM_SIG_USE_DEFAULT);
    return;
  }

  char line[512];
  alpm_db_t *cur_db = NULL; // Repo section currently being parsed

  // $arch for Server URLs; "Architecture = auto" resolves to uname -m
  struct utsname uts;
  char arch[sizeof(uts.machine)] = "x86_64";
  if (uname(&uts) == 0)
    snprintf(arch, sizeof(arch), "%s", uts.machine);

  while (fgets(line, sizeof(line), fp)) {
    // Trim leading whitespace
    char *p = line;
    while (*p == ' ' || *p == '\t')
      p++;

    // Look for section header [repository_name]
    if (*p == '[') {
      char *end = strchr(p, ']');
      if (end) {
        *end = '\0';
        char *repo_name = p + 1;
        cur_db = NULL;
        // Ignore the [options] block
        if (strcmp(repo_name, "options") != 0) {
          cur_db =
              alpm_register_syncdb(handle, repo_name, ALPM_SIG_USE_DEFAULT);
        }
      }
    } else if (cur_db && strncmp(p, "Server", 6) == 0) {
      char *v = conf_value(p);
      if (v)
        add_repo_server(cur_db, v, arch);
    } else if (cur_db && strncmp(p, "Include", 7) == 0) {
      char *v = conf_value(p);
      if (v)
        add_servers_from_include(cur_db, v, arch);
    } else if (strncmp(p, "Architecture", 12) == 0) {
      // Only the first listed architecture is used for $arch expansion
      char *v = conf_value(p);
      if (v) {
        v[strcspn(v, " \t")] = '\0';
        if (strcmp(v, "auto") != 0)
          snprintf(arch, sizeof(arch), "%s", v);
      }
    } else if (strncmp(p, "IgnorePkg", 9) == 0 ||
               strncmp(p, "IgnoreGroup", 11) == 0) {
      // Register ignored packages/groups so telemetry matches pacman's behavior
      int is_group = (strncmp(p, "IgnoreGroup", 11) == 0);
      char *eq = strchr(p, '=');
      if (eq) {
        char *tok = strtok(eq + 1, " \t\r\n");
        while (tok) {
          if (is_group)
            alpm_option_add_ignoregroup(handle, tok);
          else
            alpm_option_add_ignorepkg(handle, tok);
          tok = strtok(NULL, " \t\r\n");
        }
      }
    }
  }
  fclose(fp);
}

// Copies a system sync DB into the private dbpath if the private copy is
// missing or older, preserving mtime so libalpm's If-Modified-Since check
// skips re-downloading repos that haven't changed upstream.
static void seed_sync_db(const char *src, const char *dst) {
  struct stat ss, ds;
  if (stat(src, &ss) != 0)
    return;
  if (stat(dst, &ds) == 0 && ds.st_mtime >= ss.st_mtime)
    return;

  char part[PATH_MAX];
  if (snprintf(part, sizeof(part), "%s.upgrade-tmp", dst) >= (int)sizeof(part))
    return;

  FILE *in = fopen(src, "rb");
  if (!in)
    return;
  FILE *out = fopen(part, "wb");
  if (!out) {
    fclose(in);
    return;
  }

  char buf[65536];
  size_t n;
  int ok = 1;
  while ((n = fread(buf, 1, sizeof(buf), in)) > 0) {
    if (fwrite(buf, 1, n, out) != n) {
      ok = 0;
      break;
    }
  }
  if (ferror(in))
    ok = 0;
  fclose(in);
  if (fclose(out) != 0)
    ok = 0;

  if (ok) {
    struct timespec times[2] = {ss.st_atim, ss.st_mtim};
    utimensat(AT_FDCWD, part, times, 0);
    if (rename(part, dst) == 0)
      return;
  }
  unlink(part);
}

// Prepares a private, user-owned dbpath (same trick as checkupdates):
//   ${TMPDIR:-/tmp}/upgrade-db-<uid>/local -> /var/lib/pacman/local
//   ${TMPDIR:-/tmp}/upgrade-db-<uid>/sync/  (seeded from /var/lib/pacman/sync)
// libalpm itself never checks the UID, so with a writable dbpath it can lock
// and refresh sync DBs without root while leaving the system DBs untouched.
// Returns 0 on success, -1 if the directory is unsafe or cannot be set up.
static int prepare_tmp_dbpath(char *out, size_t out_sz) {
  const char *tmp = getenv("TMPDIR");
  if (!tmp || tmp[0] != '/')
    tmp = "/tmp";

  uid_t uid = getuid();
  if (snprintf(out, out_sz, "%s/upgrade-db-%u", tmp, (unsigned)uid) >=
      (int)out_sz)
    return -1;
  if (mkdir(out, 0700) != 0 && errno != EEXIST)
    return -1;

  // Refuse a pre-planted dir/symlink in a shared /tmp
  struct stat st;
  if (lstat(out, &st) != 0 || !S_ISDIR(st.st_mode) || st.st_uid != uid ||
      (st.st_mode & 077) != 0)
    return -1;

  char path[PATH_MAX], target[PATH_MAX];
  if (snprintf(path, sizeof(path), "%s/local", out) >= (int)sizeof(path))
    return -1;
  if (symlink("/var/lib/pacman/local", path) != 0 && errno != EEXIST)
    return -1;
  ssize_t tlen = readlink(path, target, sizeof(target) - 1);
  if (tlen < 0)
    return -1;
  target[tlen] = '\0';
  if (strcmp(target, "/var/lib/pacman/local") != 0)
    return -1;

  if (snprintf(path, sizeof(path), "%s/sync", out) >= (int)sizeof(path))
    return -1;
  if (mkdir(path, 0755) != 0 && errno != EEXIST)
    return -1;

  DIR *d = opendir("/var/lib/pacman/sync");
  if (d) {
    struct dirent *ent;
    while ((ent = readdir(d)) != NULL) {
      size_t len = strlen(ent->d_name);
      if (len < 4 || strcmp(ent->d_name + len - 3, ".db") != 0)
        continue;
      char src[PATH_MAX], dst[PATH_MAX];
      if (snprintf(src, sizeof(src), "/var/lib/pacman/sync/%s", ent->d_name) >=
              (int)sizeof(src) ||
          snprintf(dst, sizeof(dst), "%s/%s", path, ent->d_name) >=
              (int)sizeof(dst))
        continue;
      seed_sync_db(src, dst);
    }
    closedir(d);
  }
  return 0;
}

// In read-only check mode (`check_only == 1`), refreshes sync DBs into a
// private user-owned dbpath, compares repo + AUR versions, and checks Arch
// News. During a full upgrade (`check_only == 0`), avoids duplicating the
// sync DB download (and AUR RPC query when yay/paru is present) since step [1]
// immediately runs `-Syu`.
static void run_alpm_telemetry(int check_only, int has_aur_helper) {
  // Fast path for full upgrade when yay/paru will handle repo + AUR sync itself:
  // only check Arch Linux News before upgrading.
  if (!check_only && has_aur_helper) {
    curl_global_init(CURL_GLOBAL_DEFAULT);
    CURL *curl = curl_easy_init();
    if (curl) {
      check_arch_news(curl);
      curl_easy_cleanup(curl);
    }
    curl_global_cleanup();
    return;
  }

  struct timespec t0, t1;
  clock_gettime(CLOCK_MONOTONIC, &t0);

  alpm_errno_t err;
  // Only download private sync DBs in `-c` check mode; full upgrade is about
  // to run `pacman -Syu` directly.
  char tmp_dbpath[PATH_MAX];
  int fresh =
      check_only && (prepare_tmp_dbpath(tmp_dbpath, sizeof(tmp_dbpath)) == 0);
  alpm_handle_t *handle =
      alpm_initialize("/", fresh ? tmp_dbpath : "/var/lib/pacman", &err);
  if (!handle && fresh) {
    fresh = 0;
    handle = alpm_initialize("/", "/var/lib/pacman", &err);
  }
  if (!handle) {
    fprintf(stderr, "Failed to initialize alpm: %s\n", alpm_strerror(err));
    return;
  }

  if (fresh) {
    // Display-only handle: skip DB signature checks, since root's
    // /etc/pacman.d/gnupg keyring isn't usable by an unprivileged gpgme.
    // The real `yay -Syu` (pacman as root) still verifies everything.
    alpm_option_set_default_siglevel(handle, 0);
    alpm_option_set_parallel_downloads(handle, 5);
  }

  // Auto-discover repositories from /etc/pacman.conf
  register_pacman_repos(handle);

  alpm_db_t *localdb = alpm_get_localdb(handle);
  alpm_list_t *syncdbs = alpm_get_syncdbs(handle);

  if (fresh) {
    printf(CLR_CYAN ":: Refreshing sync DBs into %s (no root needed)...\n"
                    CLR_RESET,
           tmp_dbpath);
    if (alpm_db_update(handle, syncdbs, 0) < 0) {
      fprintf(stderr,
              CLR_YELLOW ":: Warning: Could not refresh all sync DBs (%s); "
                         "using last downloaded copies.\n" CLR_RESET,
              alpm_strerror(alpm_errno(handle)));
    }
  }

  alpm_list_t *pkgcache = alpm_db_get_pkgcache(localdb);

  size_t total_pkgs = 0, foreign_count = 0, repo_updates = 0;
  off_t total_bytes = 0;

  size_t foreign_cap = 128;
  struct foreign_pkg *foreign =
      malloc(foreign_cap * sizeof(struct foreign_pkg));
  if (!foreign) {
    alpm_release(handle);
    return;
  }

  printf(CLR_CYAN
         ":: Auditing /var/lib/pacman via libalpm & AUR RPC v5...\n" CLR_RESET);

  for (alpm_list_t *i = pkgcache; i != NULL; i = alpm_list_next(i)) {
    alpm_pkg_t *local_pkg = i->data;
    const char *name = alpm_pkg_get_name(local_pkg);
    const char *local_ver = alpm_pkg_get_version(local_pkg);

    total_pkgs++;
    total_bytes += alpm_pkg_get_isize(local_pkg);

    // Check if the package exists in any configured official sync repository
    alpm_pkg_t *sync_pkg = NULL;
    for (alpm_list_t *j = syncdbs; j != NULL; j = alpm_list_next(j)) {
      sync_pkg = alpm_db_get_pkg(j->data, name);
      if (sync_pkg)
        break;
    }

    if (!sync_pkg) {
      // Not in any official repo -> foreign/AUR package
      if (foreign_count == foreign_cap) {
        size_t new_cap = foreign_cap * 2;
        struct foreign_pkg *tmp =
            realloc(foreign, new_cap * sizeof(struct foreign_pkg));
        if (!tmp) {
          free(foreign);
          alpm_release(handle);
          return;
        }
        foreign = tmp;
        foreign_cap = new_cap;
      }
      foreign[foreign_count].name = name;
      foreign[foreign_count].ver = local_ver;
      foreign[foreign_count].in_aur = 0;
      foreign[foreign_count].ignored =
          alpm_pkg_should_ignore(handle, local_pkg) ? 1 : 0;
      foreign[foreign_count].out_of_date = 0;
      foreign[foreign_count].orphaned = 0;
      foreign_count++;
    } else if (check_only) {
      // Official repo package -> compare live sync DB version vs installed
      const char *sync_ver = alpm_pkg_get_version(sync_pkg);
      if (alpm_pkg_vercmp(sync_ver, local_ver) > 0 &&
          !alpm_pkg_should_ignore(handle, local_pkg)) {
        if (repo_updates == 0) {
          printf(CLR_YELLOW "\n[!] Pending Repo Updates (%s):\n" CLR_RESET,
                 fresh ? "live sync DBs" : "cached in sync DBs");
        }
        printf("    %-28s %s -> " CLR_GREEN "%s" CLR_RESET "\n", name,
               local_ver, sync_ver);
        repo_updates++;
      }
    }
  }

  // Audit foreign packages against AUR RPC v5 and check Arch Linux News
  size_t aur_updates = 0;
  curl_global_init(CURL_GLOBAL_DEFAULT);
  CURL *curl = curl_easy_init();
  if (curl) {
    if (foreign_count > 0)
      aur_updates = audit_aur_packages(curl, foreign, foreign_count);
    check_arch_news(curl);
    curl_easy_cleanup(curl);
  }
  curl_global_cleanup();

  clock_gettime(CLOCK_MONOTONIC, &t1);
  double elapsed_ms =
      (t1.tv_sec - t0.tv_sec) * 1000.0 + (t1.tv_nsec - t0.tv_nsec) / 1e6;
  double total_gib = (double)total_bytes / (1024.0 * 1024.0 * 1024.0);

  printf(CLR_CYAN "\n:: ALPM Telemetry Summary (%.1f ms):\n" CLR_RESET,
         elapsed_ms);
  printf("   Installed : %zu packages (%.2f GiB) | Foreign: %zu (%zu AUR "
         "updates)\n",
         total_pkgs, total_gib, foreign_count, aur_updates);

  free(foreign);
  alpm_release(handle);
}

// Verifies that the filesystem backing `path` has at least `min_gib` GiB of
// unprivileged free space (f_bavail * f_frsize). Fails closed (-1) on error.
static int check_disk_space(const char *path, double min_gib) {
  struct statvfs vfs;
  if (statvfs(path, &vfs) != 0) {
    fprintf(stderr, CLR_RED ":: Error: Cannot statvfs '%s': %s\n" CLR_RESET,
            path, strerror(errno));
    return -1;
  }

  unsigned long long free_bytes =
      (unsigned long long)vfs.f_bavail * vfs.f_frsize;
  double free_gib = (double)free_bytes / (1024.0 * 1024.0 * 1024.0);

  if (free_gib < min_gib) {
    fprintf(stderr,
            CLR_RED ":: Error: Low disk space on '%s' (%.2f GiB free, need >= "
                    "%.1f GiB).\n" CLR_RESET,
            path, free_gib, min_gib);
    return -1;
  }
  printf(CLR_GREEN "[✓] Storage check '%s': %.2f GiB available.\n" CLR_RESET,
         path, free_gib);
  return 0;
}

// Checks whether the currently running kernel's module directory
// (/lib/modules/$(uname -r)) still exists on disk. On Arch Linux, upgrading
// the `linux` package removes the old kernel's modules immediately, meaning a
// reboot is needed before loading new kernel modules.
static void check_kernel_reboot(void) {
  struct utsname uts;
  if (uname(&uts) != 0)
    return;

  char mod_path[512];
  snprintf(mod_path, sizeof(mod_path), "/lib/modules/%s", uts.release);

  if (access(mod_path, F_OK) != 0) {
    printf(CLR_RED "\n[!] KERNEL UPDATED: Running '%s', but its modules were "
                   "replaced on disk.\n"
                   "    Reboot soon before hotplugging hardware or loading "
                   "kernel modules.\n" CLR_RESET,
           uts.release);
  } else {
    printf(CLR_GREEN "\n[✓] Kernel modules intact (%s) — no immediate reboot "
                     "required.\n" CLR_RESET,
           uts.release);
  }
}

// Scans /proc/<pid>/exe and /proc/<pid>/maps for processes that are still
// running a deleted executable or holding deleted /usr/lib/*.so shared
// libraries in RAM after an upgrade, deduplicating by /proc/<pid>/comm.
static void check_stale_libs(void) {
  DIR *proc = opendir("/proc");
  if (!proc)
    return;

  struct dirent *ent;
  int stale_count = 0;
  int hidden = 0; // Processes we lack permission to inspect (EACCES)
  pid_t self = getpid();
  int as_root = (geteuid() == 0);
  char seen_comms[64][64];
  int seen_count = 0;

  // Our own name, so the parent upgrade (started before the upgrade and thus
  // possibly mapping now-deleted libcurl/libalpm) isn't reported.
  char self_comm[64] = "";
  FILE *sf = fopen("/proc/self/comm", "r");
  if (sf) {
    if (fgets(self_comm, sizeof(self_comm), sf))
      self_comm[strcspn(self_comm, "\n")] = '\0';
    fclose(sf);
  }

  while ((ent = readdir(proc)) != NULL) {
    if (!isdigit((unsigned char)ent->d_name[0]))
      continue;

    pid_t pid = (pid_t)atoi(ent->d_name);
    if (pid <= 0 || pid == self)
      continue;

    char deleted_lib[256] = "";

    // 1. Check whether the process's main executable binary itself was replaced
    char exe_path[64], exe_buf[240];
    snprintf(exe_path, sizeof(exe_path), "/proc/%d/exe", (int)pid);
    ssize_t elen = readlink(exe_path, exe_buf, sizeof(exe_buf) - 1);
    if (elen > 10) {
      exe_buf[elen] = '\0';
      if (strcmp(exe_buf + elen - 10, " (deleted)") == 0) {
        exe_buf[elen - 10] = '\0';
        snprintf(deleted_lib, sizeof(deleted_lib), "[exe] %s", exe_buf);
      }
    }

    // 2. Otherwise inspect memory mappings for deleted shared libraries
    if (deleted_lib[0] == '\0') {
      char maps_path[64];
      snprintf(maps_path, sizeof(maps_path), "/proc/%d/maps", (int)pid);

      FILE *fp = fopen(maps_path, "r");
      if (!fp) {
        if (errno == EACCES)
          hidden++;
        continue;
      }

      char line[1024];
      while (fgets(line, sizeof(line), fp)) {
        const char *usr_lib = strstr(line, "/usr/lib/");
        if (!usr_lib)
          usr_lib = strstr(line, "/lib/");
        if (usr_lib && strstr(usr_lib, ".so") && strstr(usr_lib, "(deleted)")) {
          snprintf(deleted_lib, sizeof(deleted_lib), "%s", usr_lib);
          deleted_lib[strcspn(deleted_lib, " \t\n")] = '\0';
          break;
        }
      }
      fclose(fp);
    }

    if (deleted_lib[0] != '\0') {
      char comm_path[64];
      char comm[64] = "unknown";
      snprintf(comm_path, sizeof(comm_path), "/proc/%d/comm", (int)pid);

      FILE *cf = fopen(comm_path, "r");
      if (cf) {
        if (fgets(comm, sizeof(comm), cf)) {
          comm[strcspn(comm, "\n")] = '\0';
        }
        fclose(cf);
      }

      // Deduplicate by process comm name so multi-process apps (e.g. browsers)
      // only appear once in the output
      int already_seen = (self_comm[0] != '\0' && strcmp(comm, self_comm) == 0);
      for (int i = 0; i < seen_count; i++) {
        if (strcmp(seen_comms[i], comm) == 0) {
          already_seen = 1;
          break;
        }
      }
      if (already_seen)
        continue;
      if (seen_count < 64) {
        snprintf(seen_comms[seen_count++], 64, "%s", comm);
      }

      if (stale_count == 0) {
        printf(CLR_YELLOW "\n[!] %s processes running deleted binaries or "
                          "shared libraries in RAM:\n" CLR_RESET,
               as_root ? "System/user" : "User");
      }
      printf("    - %-18s (PID %-6d) -> %s\n", comm, (int)pid, deleted_lib);
      stale_count++;
    }
  }
  closedir(proc);

  if (stale_count == 0) {
    printf(CLR_GREEN "[✓] No %sprocesses holding stale binaries or shared "
                     "libraries.\n" CLR_RESET,
           as_root ? "" : "user ");
  }
  if (hidden > 0) {
    printf(CLR_MAGENTA "    (%d processes owned by other users/root were not "
                       "inspected — needs root)\n" CLR_RESET,
           hidden);
  }
}

// Returns 1 if `name` resolves to an executable somewhere in $PATH
static int have_cmd(const char *name) {
  const char *path = getenv("PATH");
  if (!path || !*path)
    path = "/usr/local/bin:/usr/bin:/bin";

  char buf[PATH_MAX];
  size_t name_len = strlen(name);
  const char *p = path;
  for (;;) {
    const char *colon = strchr(p, ':');
    size_t len = colon ? (size_t)(colon - p) : strlen(p);
    if (len > 0 && len + 1 + name_len < sizeof(buf)) {
      memcpy(buf, p, len);
      buf[len] = '/';
      memcpy(buf + len + 1, name, name_len + 1);
      if (access(buf, X_OK) == 0)
        return 1;
    }
    if (!colon)
      return 0;
    p = colon + 1;
  }
}

// Runs pacman's native local-database consistency audit (`pacman -Dkq`), which
// checks dependency satisfaction, package conflicts, required database files,
// and duplicate file ownership. Read-only and does not need root.
static void check_package_database(void) {
  if (!have_cmd("pacman")) {
    printf(CLR_YELLOW "[!] Package database check skipped: pacman not found.\n"
                      CLR_RESET);
    return;
  }

  if (access("/var/lib/pacman/db.lck", F_OK) == 0) {
    printf(CLR_YELLOW "[!] Package database check skipped: pacman database is "
                      "locked.\n" CLR_RESET);
    return;
  }

  char *const cmd[] = {"pacman", "-Dkq", NULL};
  int rc = run_cmd(cmd);
  if (rc == 0) {
    printf(CLR_GREEN "[✓] Local package database consistency check passed.\n"
                     CLR_RESET);
  } else if (rc == -2) {
    printf(CLR_YELLOW "[!] Package database check interrupted.\n" CLR_RESET);
  } else {
    printf(CLR_RED "[!] Package database check reported problems; review the "
                   "pacman output above.\n" CLR_RESET);
  }
}

// Audits registered DKMS kernel module builds (when `dkms` is installed).
// Pacman hooks do not fail the transaction when a DKMS module fails to build
// against a newly installed kernel, so verifying `: installed` catches broken
// out-of-tree drivers before rebooting.
static void check_dkms_status(void) {
  if (!have_cmd("dkms"))
    return;

  char buf[8192];
  int rc = -1;
  if (capture_cmd_output((char *const[]){"dkms", "status", NULL}, buf,
                         sizeof(buf), &rc) < 0)
    return;

  size_t total = 0, broken = 0;
  const char *p = buf;
  while (*p != '\0') {
    const char *nl = strchr(p, '\n');
    size_t len = nl ? (size_t)(nl - p) : strlen(p);
    if (len > 0) {
      total++;
      // Check whether this line reports `: installed`
      int ok = 0;
      for (size_t i = 0; i + 11 <= len; i++) {
        if (memcmp(p + i, ": installed", 11) == 0) {
          ok = 1;
          break;
        }
      }
      if (!ok)
        broken++;
    }
    if (!nl)
      break;
    p = nl + 1;
  }

  if (total == 0 && rc == 0)
    return;

  if (rc != 0 || broken > 0) {
    printf(CLR_YELLOW "[!] Incomplete or broken DKMS kernel module builds:\n"
                      CLR_RESET);
    print_indented_lines(buf);
  } else {
    printf(CLR_GREEN "[✓] DKMS modules healthy (%zu installed).\n" CLR_RESET,
           total);
  }
}

// Returns 1 if `opt` appears as an exact comma-separated token in `csv`.
static int has_csv_opt(const char *csv, const char *opt) {
  size_t olen = strlen(opt);
  const char *p = csv;
  while (*p != '\0') {
    const char *comma = strchr(p, ',');
    size_t len = comma ? (size_t)(comma - p) : strlen(p);
    if (len == olen && strncmp(p, opt, olen) == 0)
      return 1;
    if (!comma)
      break;
    p = comma + 1;
  }
  return 0;
}

// Checks /proc/self/mountinfo (after stat'ing `target` to trigger any
// x-systemd.automount autofs unit) to determine whether `target` has a real
// filesystem mounted on it and whether that mount is read-only (`ro`).
static void inspect_mountpoint(const char *target, int *is_mounted,
                               int *is_ro) {
  *is_mounted = 0;
  *is_ro = 0;

  struct stat st;
  (void)stat(target, &st); // Trigger autofs if configured

  FILE *fp = fopen("/proc/self/mountinfo", "r");
  if (!fp)
    return;

  char line[1024];
  while (fgets(line, sizeof(line), fp)) {
    char mnt[512], opts[256], fstype[64];
    if (sscanf(line, "%*s %*s %*s %*s %511s %255s", mnt, opts) != 2)
      continue;
    if (strcmp(mnt, target) != 0)
      continue;
    const char *sep = strstr(line, " - ");
    if (!sep || sscanf(sep + 3, "%63s", fstype) != 1)
      continue;
    if (strcmp(fstype, "autofs") == 0)
      continue;

    *is_mounted = 1;
    *is_ro = has_csv_opt(opts, "ro");
  }
  fclose(fp);
}

// Verifies that any /boot, /efi, or /boot/efi partition listed in /etc/fstab
// (without `noauto`) is actually mounted before kernel/initramfs upgrades can
// write to an unmounted directory on `/`, and checks that active boot/ESP
// mounts are writable (`rw`) with at least 0.15 GiB free.
static int check_boot_mounts(int check_only) {
  int failed = 0;

  FILE *fp = fopen("/etc/fstab", "r");
  if (fp) {
    char line[1024];
    while (fgets(line, sizeof(line), fp)) {
      char *p = line;
      while (*p == ' ' || *p == '\t')
        p++;
      if (*p == '#' || *p == '\n' || *p == '\r' || *p == '\0')
        continue;

      char spec[256], mnt[256], fstype[64], opts[256];
      if (sscanf(p, "%255s %255s %63s %255s", spec, mnt, fstype, opts) < 4)
        continue;
      size_t mlen = strlen(mnt);
      while (mlen > 1 && mnt[mlen - 1] == '/')
        mnt[--mlen] = '\0';

      if (strcmp(mnt, "/boot") != 0 && strcmp(mnt, "/efi") != 0 &&
          strcmp(mnt, "/boot/efi") != 0)
        continue;
      if (has_csv_opt(opts, "noauto"))
        continue;

      int mounted = 0, ro = 0;
      inspect_mountpoint(mnt, &mounted, &ro);
      if (!mounted) {
        if (check_only) {
          printf(CLR_RED "[!] Boot/ESP partition '%s' is in /etc/fstab but NOT "
                         "mounted!\n" CLR_RESET,
                 mnt);
        } else {
          fprintf(stderr,
                  CLR_RED ":: Error: Boot/ESP partition '%s' is in /etc/fstab "
                          "but NOT mounted!\n"
                          "   Mount '%s' before upgrading so kernel/initramfs "
                          "files land on the ESP.\n" CLR_RESET,
                  mnt, mnt);
        }
        failed = 1;
      }
    }
    fclose(fp);
  }

  static const char *const candidates[3] = {"/boot", "/efi", "/boot/efi"};
  int any_separate_mount = 0;
  for (int i = 0; i < 3; i++) {
    int mounted = 0, ro = 0;
    inspect_mountpoint(candidates[i], &mounted, &ro);
    if (!mounted)
      continue;
    any_separate_mount = 1;

    if (ro) {
      if (check_only) {
        printf(CLR_RED "[!] Boot/ESP mount '%s' is mounted read-only (ro)!\n"
                       CLR_RESET,
               candidates[i]);
      } else {
        fprintf(stderr,
                CLR_RED ":: Error: Boot/ESP mount '%s' is mounted read-only "
                        "(ro)!\n" CLR_RESET,
                candidates[i]);
      }
      failed = 1;
      continue;
    }

    if (check_only) {
      struct statvfs vfs;
      if (statvfs(candidates[i], &vfs) == 0) {
        double free_gib = ((double)vfs.f_bavail * (double)vfs.f_frsize) /
                          (1024.0 * 1024.0 * 1024.0);
        if (free_gib < 0.15) {
          printf(CLR_RED "[!] Low free space on '%s': %.2f GiB available "
                         "(need >= 0.15 GiB)!\n" CLR_RESET,
                 candidates[i], free_gib);
          failed = 1;
        } else {
          printf(CLR_GREEN "[✓] Boot/ESP mount '%s': mounted rw (%.2f GiB "
                           "available).\n" CLR_RESET,
                 candidates[i], free_gib);
        }
      } else {
        printf(CLR_GREEN "[✓] Boot/ESP mount '%s': mounted rw.\n" CLR_RESET,
               candidates[i]);
      }
    } else {
      struct statvfs probe;
      if (statvfs(candidates[i], &probe) != 0 && errno == EACCES &&
          geteuid() != 0)
        continue;
      if (check_disk_space(candidates[i], 0.15) != 0)
        failed = 1;
    }
  }

  // Single-partition layout where /boot lives directly on `/`
  if (!any_separate_mount && !check_only && access("/boot", F_OK) == 0) {
    if (check_disk_space("/boot", 0.15) != 0)
      failed = 1;
  }

  return failed ? -1 : 0;
}

// Reports the previous boot's total startup time and its critical dependency
// chain. This is diagnostic only: it does not restart or alter any units.
static void check_boot_performance(void) {
  if (access("/run/systemd/system", F_OK) != 0)
    return;
  if (!have_cmd("systemd-analyze")) {
    printf(CLR_MAGENTA "[i] Boot analysis unavailable: systemd-analyze not "
                       "installed.\n" CLR_RESET);
    return;
  }

  printf(CLR_CYAN "\n:: Last boot timing...\n" CLR_RESET);
  char *const time_cmd[] = {"systemd-analyze", "--no-pager", "time", NULL};
  if (run_cmd(time_cmd) != 0) {
    printf(CLR_YELLOW "[!] Could not read systemd boot timing.\n" CLR_RESET);
    return;
  }

  printf(CLR_CYAN "\n:: Last boot critical chain...\n" CLR_RESET);
  char *const chain_cmd[] = {"systemd-analyze", "--no-pager",
                             "critical-chain", NULL};
  if (run_cmd(chain_cmd) != 0)
    printf(CLR_YELLOW "[!] Could not read the systemd critical boot chain.\n"
                      CLR_RESET);
}

// PID of the background sudo keep-alive child (-1 when not running)
static pid_t g_sudo_keepalive = -1;

static void stop_sudo_keepalive(void) {
  if (g_sudo_keepalive > 0) {
    kill(g_sudo_keepalive, SIGTERM);
    waitpid(g_sudo_keepalive, NULL, 0);
    g_sudo_keepalive = -1;
  }
}

// Obtains sudo rights once for the whole run: reuses a still-valid sudo
// timestamp if there is one, otherwise sudo prompts the user for their
// password a single time. A background child then refreshes the timestamp
// every 60 s, so yay/paru/makepkg, pacman, flatpak, snap and paccache never
// re-prompt mid-run (long AUR builds easily exceed sudo's 5 min default).
// The password is handled entirely by sudo; upgrade never sees or stores it.
static int acquire_sudo(void) {
  printf(CLR_CYAN "\n:: Requesting sudo privileges (asked at most once per "
                  "run)...\n" CLR_RESET);
  char *const sudo_validate[] = {"sudo", "-v", NULL};
  if (run_cmd(sudo_validate) != 0)
    return -1;

  pid_t parent = getpid();
  fflush(NULL);
  pid_t pid = fork();
  if (pid < 0)
    return 0; // Non-fatal: sudo may simply re-prompt later
  if (pid == 0) {
    // Die together with upgrade, however it exits (Ctrl+C, crash, ...)
    prctl(PR_SET_PDEATHSIG, SIGTERM);
    if (getppid() != parent)
      _exit(0);

    // Keep quiet: never write into the user's terminal output
    int devnull = open("/dev/null", O_RDWR);
    if (devnull >= 0) {
      dup2(devnull, STDIN_FILENO);
      dup2(devnull, STDOUT_FILENO);
      dup2(devnull, STDERR_FILENO);
      if (devnull > STDERR_FILENO)
        close(devnull);
    }

    char *const sudo_refresh[] = {"sudo", "-n", "-v", NULL};
    for (;;) {
      sleep(60);
      if (getppid() != parent || run_cmd(sudo_refresh) != 0)
        _exit(0);
    }
  }

  g_sudo_keepalive = pid;
  atexit(stop_sudo_keepalive);
  return 0;
}

// Detects true orphaned dependencies via libalpm (`pacman -Qdtq` equivalent:
// installed as a dependency and neither required nor optionally required by any
// package). Skips spawning an external helper altogether when 0 orphans exist.
static void sweep_orphans(const char *aur_helper, int auto_yes) {
  alpm_errno_t err;
  alpm_handle_t *handle = alpm_initialize("/", "/var/lib/pacman", &err);
  if (!handle)
    return;

  alpm_db_t *localdb = alpm_get_localdb(handle);
  size_t cap = 16, count = 0;
  char **orphans = malloc(cap * sizeof(char *));
  if (!orphans) {
    alpm_release(handle);
    return;
  }

  for (alpm_list_t *i = alpm_db_get_pkgcache(localdb); i != NULL;
       i = alpm_list_next(i)) {
    alpm_pkg_t *pkg = i->data;
    if (alpm_pkg_get_reason(pkg) != ALPM_PKG_REASON_DEPEND)
      continue;

    alpm_list_t *req = alpm_pkg_compute_requiredby(pkg);
    if (req) {
      FREELIST(req);
      continue;
    }
    alpm_list_t *opt = alpm_pkg_compute_optionalfor(pkg);
    if (opt) {
      FREELIST(opt);
      continue;
    }

    if (count == cap) {
      char **tmp = realloc(orphans, cap * 2 * sizeof(char *));
      if (!tmp)
        break;
      orphans = tmp;
      cap *= 2;
    }
    orphans[count] = strdup(alpm_pkg_get_name(pkg));
    if (orphans[count])
      count++;
  }
  alpm_release(handle);

  if (count == 0) {
    printf(CLR_GREEN "[✓] No orphaned dependencies.\n" CLR_RESET);
    free(orphans);
    return;
  }

  printf(CLR_YELLOW "    Found %zu orphaned package(s):" CLR_RESET, count);
  for (size_t i = 0; i < count; i++)
    printf(" %s", orphans[i]);
  printf("\n");

  char *noconfirm = auto_yes ? "--noconfirm" : NULL;
  if (aur_helper && strcmp(aur_helper, "yay") == 0) {
    char *const cmd[] = {"yay", "-Yc", noconfirm, NULL};
    run_cmd(cmd);
  } else if (aur_helper && strcmp(aur_helper, "paru") == 0) {
    char *const cmd[] = {"paru", "-c", noconfirm, NULL};
    run_cmd(cmd);
  } else {
    char **args = malloc((count + 5) * sizeof(char *));
    if (args) {
      size_t n = 0;
      args[n++] = "sudo";
      args[n++] = "pacman";
      args[n++] = "-Rns";
      if (auto_yes)
        args[n++] = "--noconfirm";
      for (size_t i = 0; i < count; i++)
        args[n++] = orphans[i];
      args[n] = NULL;
      run_cmd(args);
      free(args);
    }
  }

  for (size_t i = 0; i < count; i++)
    free(orphans[i]);
  free(orphans);
}

// Removes leftover `download-XXXXXX` sandbox directories left behind by
// interrupted Pacman 7 downloads when no db.lck is active.
static void sweep_download_dirs(const char *parent, size_t *dirs_removed,
                                unsigned long long *bytes_freed) {
  DIR *d = opendir(parent);
  if (!d)
    return;

  struct dirent *ent;
  while ((ent = readdir(d)) != NULL) {
    if (strncmp(ent->d_name, "download-", 9) != 0)
      continue;

    char sub[PATH_MAX];
    if (snprintf(sub, sizeof(sub), "%s/%s", parent, ent->d_name) >=
        (int)sizeof(sub))
      continue;

    struct stat st;
    if (lstat(sub, &st) != 0 || !S_ISDIR(st.st_mode))
      continue;

    DIR *sd = opendir(sub);
    if (sd) {
      struct dirent *se;
      while ((se = readdir(sd)) != NULL) {
        if (strcmp(se->d_name, ".") == 0 || strcmp(se->d_name, "..") == 0)
          continue;
        char fp[PATH_MAX];
        if (snprintf(fp, sizeof(fp), "%s/%s", sub, se->d_name) >=
            (int)sizeof(fp))
          continue;
        struct stat fst;
        if (lstat(fp, &fst) == 0 && !S_ISDIR(fst.st_mode)) {
          if (unlink(fp) == 0 && S_ISREG(fst.st_mode))
            *bytes_freed += (unsigned long long)fst.st_size;
        }
      }
      closedir(sd);
    }
    if (rmdir(sub) == 0)
      (*dirs_removed)++;
  }
  closedir(d);
}

struct cached_pkg {
  char *filename;
  char *pkgname;
  char *ver;
};

static int cmp_cached_pkg(const void *a, const void *b) {
  const struct cached_pkg *pa = (const struct cached_pkg *)a;
  const struct cached_pkg *pb = (const struct cached_pkg *)b;
  int c = strcmp(pa->pkgname, pb->pkgname);
  if (c != 0)
    return c;
  // Sort newest version first within each package group
  return alpm_pkg_vercmp(pb->ver, pa->ver);
}

// Parses `<pkgname>-<pkgver>-<pkgrel>-<arch>.pkg.tar*` into `out` (returns 0 on
// match, -1 for non-package or `.sig`/`.part` files).
static int parse_cached_pkg(const char *fname, struct cached_pkg *out) {
  const char *ext = strstr(fname, ".pkg.tar");
  if (!ext || ext == fname)
    return -1;
  size_t flen = strlen(fname);
  if ((flen >= 4 && strcmp(fname + flen - 4, ".sig") == 0) ||
      (flen >= 5 && strcmp(fname + flen - 5, ".part") == 0))
    return -1;

  // Locate the last 3 hyphens before `.pkg.tar`: -<pkgver>-<pkgrel>-<arch>
  const char *h3 = NULL, *h2 = NULL, *h1 = NULL;
  for (const char *p = ext - 1; p > fname; p--) {
    if (*p == '-') {
      if (!h3)
        h3 = p;
      else if (!h2)
        h2 = p;
      else {
        h1 = p;
        break;
      }
    }
  }
  if (!h1 || h1 == fname || h2 == h1 + 1 || h3 == h2 + 1)
    return -1;

  out->filename = strdup(fname);
  out->pkgname = strndup(fname, (size_t)(h1 - fname));
  size_t vlen = (size_t)(h3 - (h1 + 1));
  out->ver = malloc(vlen + 1);
  if (!out->filename || !out->pkgname || !out->ver) {
    free(out->filename);
    free(out->pkgname);
    free(out->ver);
    return -1;
  }

  // Decode URL-escaped '%3A' epochs back to ':' so alpm_pkg_vercmp() matches
  size_t vi = 0;
  for (const char *p = h1 + 1; p < h3;) {
    if (p + 2 < h3 && p[0] == '%' && p[1] == '3' &&
        (p[2] == 'A' || p[2] == 'a')) {
      out->ver[vi++] = ':';
      p += 3;
    } else {
      out->ver[vi++] = *p++;
    }
  }
  out->ver[vi] = '\0';
  return 0;
}

// Native replacement for `paccache -rk2` + `paccache -ruk0` + Pacman 7 stale
// sandbox cleanup. Keeps the newest 2 versions of installed packages and drops
// all cached archives for uninstalled packages.
static void clean_pacman_cache(void) {
  if (access("/var/lib/pacman/db.lck", F_OK) == 0) {
    fprintf(stderr, CLR_YELLOW ":: Skipping cache trim: db.lck is held.\n"
                               CLR_RESET);
    return;
  }

  char cachedir[PATH_MAX] = "/var/cache/pacman/pkg";
  FILE *cf = fopen("/etc/pacman.conf", "r");
  if (cf) {
    char line[512];
    while (fgets(line, sizeof(line), cf)) {
      char *p = line;
      while (*p == ' ' || *p == '\t')
        p++;
      if (strncmp(p, "CacheDir", 8) == 0) {
        char *v = conf_value(p);
        if (v) {
          size_t len = strlen(v);
          while (len > 1 && v[len - 1] == '/')
            v[--len] = '\0';
          snprintf(cachedir, sizeof(cachedir), "%s", v);
          break;
        }
      }
    }
    fclose(cf);
  }

  size_t dl_dirs = 0;
  unsigned long long freed_bytes = 0;
  sweep_download_dirs("/var/lib/pacman/sync", &dl_dirs, &freed_bytes);
  sweep_download_dirs(cachedir, &dl_dirs, &freed_bytes);

  alpm_errno_t err;
  alpm_handle_t *handle = alpm_initialize("/", "/var/lib/pacman", &err);
  if (!handle)
    return;
  alpm_db_t *localdb = alpm_get_localdb(handle);

  DIR *d = opendir(cachedir);
  if (!d) {
    alpm_release(handle);
    return;
  }

  size_t cap = 256, count = 0;
  struct cached_pkg *items = malloc(cap * sizeof(struct cached_pkg));
  if (!items) {
    closedir(d);
    alpm_release(handle);
    return;
  }

  struct dirent *ent;
  while ((ent = readdir(d)) != NULL) {
    if (count == cap) {
      struct cached_pkg *tmp =
          realloc(items, cap * 2 * sizeof(struct cached_pkg));
      if (!tmp)
        break;
      items = tmp;
      cap *= 2;
    }
    if (parse_cached_pkg(ent->d_name, &items[count]) == 0)
      count++;
  }
  closedir(d);

  qsort(items, count, sizeof(struct cached_pkg), cmp_cached_pkg);

  size_t removed_pkgs = 0;
  for (size_t i = 0; i < count;) {
    size_t j = i + 1;
    while (j < count && strcmp(items[i].pkgname, items[j].pkgname) == 0)
      j++;

    size_t keep = (alpm_db_get_pkg(localdb, items[i].pkgname) != NULL) ? 2 : 0;
    for (size_t k = i + keep; k < j; k++) {
      char path[PATH_MAX];
      if (snprintf(path, sizeof(path), "%s/%s", cachedir, items[k].filename) <
          (int)sizeof(path)) {
        struct stat st;
        if (lstat(path, &st) == 0 && unlink(path) == 0) {
          freed_bytes += (unsigned long long)st.st_size;
          removed_pkgs++;
        }
      }
      char sig[PATH_MAX];
      if (snprintf(sig, sizeof(sig), "%s/%s.sig", cachedir, items[k].filename) <
          (int)sizeof(sig)) {
        struct stat st;
        if (lstat(sig, &st) == 0 && unlink(sig) == 0)
          freed_bytes += (unsigned long long)st.st_size;
      }
    }
    i = j;
  }

  for (size_t i = 0; i < count; i++) {
    free(items[i].filename);
    free(items[i].pkgname);
    free(items[i].ver);
  }
  free(items);
  alpm_release(handle);

  if (removed_pkgs > 0) {
    double mib = (double)freed_bytes / (1024.0 * 1024.0);
    if (mib >= 1024.0) {
      printf(CLR_GREEN "[✓] Pacman cache: removed %zu stale archive(s) "
                       "(freed %.2f GiB).\n" CLR_RESET,
             removed_pkgs, mib / 1024.0);
    } else {
      printf(CLR_GREEN "[✓] Pacman cache: removed %zu stale archive(s) "
                       "(freed %.2f MiB).\n" CLR_RESET,
             removed_pkgs, mib);
    }
  } else {
    printf(CLR_GREEN
           "[✓] Pacman cache already clean (kept last 2 versions).\n"
           CLR_RESET);
  }
  if (dl_dirs > 0) {
    printf(CLR_GREEN
           "[✓] Swept %zu leftover pacman download-* temp dir(s).\n" CLR_RESET,
           dl_dirs);
  }
}

// Trims built `.pkg.tar*` archives inside ~/.cache/yay/* and
// ~/.cache/paru/clone/* using the same retention policy as clean_pacman_cache()
// (keep newest 2 versions of installed packages, drop uninstalled). Leaves
// PKGBUILDs, git clones, and source files untouched.
static void clean_aur_cache(void) {
  const char *xdg = getenv("XDG_CACHE_HOME");
  const char *home = getenv("HOME");
  char cache_base[PATH_MAX];

  if (xdg && xdg[0] == '/') {
    if (snprintf(cache_base, sizeof(cache_base), "%s", xdg) >=
        (int)sizeof(cache_base))
      return;
  } else if (home && home[0] == '/') {
    if (snprintf(cache_base, sizeof(cache_base), "%s/.cache", home) >=
        (int)sizeof(cache_base))
      return;
  } else {
    return;
  }

  static const char *const rel_roots[2] = {"yay", "paru/clone"};
  char roots[2][PATH_MAX];
  int root_count = 0;
  for (int r = 0; r < 2; r++) {
    char cand[PATH_MAX];
    struct stat st;
    if (snprintf(cand, sizeof(cand), "%s/%s", cache_base, rel_roots[r]) <
            (int)sizeof(cand) &&
        lstat(cand, &st) == 0 && S_ISDIR(st.st_mode)) {
      snprintf(roots[root_count++], PATH_MAX, "%s", cand);
    }
  }
  if (root_count == 0)
    return;

  alpm_errno_t err;
  alpm_handle_t *handle = alpm_initialize("/", "/var/lib/pacman", &err);
  if (!handle)
    return;
  alpm_db_t *localdb = alpm_get_localdb(handle);

  size_t cap = 128, count = 0;
  struct cached_pkg *items = malloc(cap * sizeof(struct cached_pkg));
  if (!items) {
    alpm_release(handle);
    return;
  }

  for (int r = 0; r < root_count; r++) {
    DIR *top = opendir(roots[r]);
    if (!top)
      continue;
    struct dirent *sub;
    while ((sub = readdir(top)) != NULL) {
      if (sub->d_name[0] == '.')
        continue;
      char pkgdir[PATH_MAX];
      if (snprintf(pkgdir, sizeof(pkgdir), "%s/%s", roots[r], sub->d_name) >=
          (int)sizeof(pkgdir))
        continue;
      struct stat dst;
      if (lstat(pkgdir, &dst) != 0 || !S_ISDIR(dst.st_mode))
        continue;

      DIR *pd = opendir(pkgdir);
      if (!pd)
        continue;
      struct dirent *fe;
      while ((fe = readdir(pd)) != NULL) {
        struct cached_pkg parsed;
        if (parse_cached_pkg(fe->d_name, &parsed) != 0)
          continue;

        char full[PATH_MAX];
        if (snprintf(full, sizeof(full), "%s/%s", pkgdir, fe->d_name) >=
            (int)sizeof(full)) {
          free(parsed.filename);
          free(parsed.pkgname);
          free(parsed.ver);
          continue;
        }
        char *full_dup = strdup(full);
        if (!full_dup) {
          free(parsed.filename);
          free(parsed.pkgname);
          free(parsed.ver);
          continue;
        }
        free(parsed.filename);
        parsed.filename = full_dup;

        if (count == cap) {
          struct cached_pkg *tmp =
              realloc(items, cap * 2 * sizeof(struct cached_pkg));
          if (!tmp) {
            free(parsed.filename);
            free(parsed.pkgname);
            free(parsed.ver);
            break;
          }
          items = tmp;
          cap *= 2;
        }
        items[count++] = parsed;
      }
      closedir(pd);
    }
    closedir(top);
  }

  qsort(items, count, sizeof(struct cached_pkg), cmp_cached_pkg);

  size_t removed_pkgs = 0;
  unsigned long long freed_bytes = 0;
  for (size_t i = 0; i < count;) {
    size_t j = i + 1;
    while (j < count && strcmp(items[i].pkgname, items[j].pkgname) == 0)
      j++;

    size_t keep = (alpm_db_get_pkg(localdb, items[i].pkgname) != NULL) ? 2 : 0;
    for (size_t k = i + keep; k < j; k++) {
      struct stat st;
      if (lstat(items[k].filename, &st) == 0 && S_ISREG(st.st_mode) &&
          unlink(items[k].filename) == 0) {
        freed_bytes += (unsigned long long)st.st_size;
        removed_pkgs++;
      }
      char sig[PATH_MAX];
      if (snprintf(sig, sizeof(sig), "%s.sig", items[k].filename) <
              (int)sizeof(sig) &&
          lstat(sig, &st) == 0 && S_ISREG(st.st_mode) && unlink(sig) == 0) {
        freed_bytes += (unsigned long long)st.st_size;
      }
    }
    i = j;
  }

  for (size_t i = 0; i < count; i++) {
    free(items[i].filename);
    free(items[i].pkgname);
    free(items[i].ver);
  }
  free(items);
  alpm_release(handle);

  if (removed_pkgs > 0) {
    double mib = (double)freed_bytes / (1024.0 * 1024.0);
    if (mib >= 1024.0) {
      printf(CLR_GREEN "[✓] AUR build cache: removed %zu stale archive(s) "
                       "(freed %.2f GiB).\n" CLR_RESET,
             removed_pkgs, mib / 1024.0);
    } else {
      printf(CLR_GREEN "[✓] AUR build cache: removed %zu stale archive(s) "
                       "(freed %.2f MiB).\n" CLR_RESET,
             removed_pkgs, mib);
    }
  } else {
    printf(CLR_GREEN
           "[✓] AUR build cache already clean (kept last 2 versions).\n"
           CLR_RESET);
  }
}

struct str_vec {
  char **items;
  size_t count;
  size_t cap;
};

static void str_vec_add_unique(struct str_vec *v, const char *s) {
  for (size_t i = 0; i < v->count; i++) {
    if (strcmp(v->items[i], s) == 0)
      return;
  }
  if (v->count == v->cap) {
    size_t ncap = v->cap ? v->cap * 2 : 16;
    char **tmp = realloc(v->items, ncap * sizeof(char *));
    if (!tmp)
      return;
    v->items = tmp;
    v->cap = ncap;
  }
  char *dup = strdup(s);
  if (dup)
    v->items[v->count++] = dup;
}

static int cmp_cstr_ptr(const void *a, const void *b) {
  return strcmp(*(char *const *)a, *(char *const *)b);
}

static void walk_etc_pacfiles(const char *dir, int depth, struct str_vec *out) {
  if (depth > 12)
    return;
  DIR *d = opendir(dir);
  if (!d)
    return;

  struct dirent *ent;
  while ((ent = readdir(d)) != NULL) {
    if (strcmp(ent->d_name, ".") == 0 || strcmp(ent->d_name, "..") == 0)
      continue;
    char path[PATH_MAX];
    if (snprintf(path, sizeof(path), "%s/%s", dir, ent->d_name) >=
        (int)sizeof(path))
      continue;

    struct stat st;
    if (lstat(path, &st) != 0)
      continue;
    if (S_ISDIR(st.st_mode)) {
      walk_etc_pacfiles(path, depth + 1, out);
    } else if (S_ISREG(st.st_mode)) {
      size_t n = strlen(ent->d_name);
      if ((n > 7 && strcmp(ent->d_name + n - 7, ".pacnew") == 0) ||
          (n > 8 && strcmp(ent->d_name + n - 8, ".pacsave") == 0) ||
          (n > 8 && strcmp(ent->d_name + n - 8, ".pacorig") == 0)) {
        str_vec_add_unique(out, path);
      }
    }
  }
  closedir(d);
}

// Native replacement for `pacdiff -o`: checks every installed package's backup
// array via libalpm AND walks /etc for .pacsave files from removed packages.
static void scan_pacnew_files(void) {
  struct str_vec found = {NULL, 0, 0};

  alpm_errno_t err;
  alpm_handle_t *handle = alpm_initialize("/", "/var/lib/pacman", &err);
  if (handle) {
    alpm_db_t *localdb = alpm_get_localdb(handle);
    static const char *const exts[3] = {".pacnew", ".pacsave", ".pacorig"};

    for (alpm_list_t *i = alpm_db_get_pkgcache(localdb); i != NULL;
         i = alpm_list_next(i)) {
      for (alpm_list_t *b = alpm_pkg_get_backup(i->data); b != NULL;
           b = alpm_list_next(b)) {
        const alpm_backup_t *bk = b->data;
        if (!bk || !bk->name)
          continue;
        for (int e = 0; e < 3; e++) {
          char path[PATH_MAX];
          if (snprintf(path, sizeof(path), "/%s%s", bk->name, exts[e]) <
              (int)sizeof(path)) {
            struct stat st;
            if (lstat(path, &st) == 0 && S_ISREG(st.st_mode))
              str_vec_add_unique(&found, path);
          }
        }
      }
    }
    alpm_release(handle);
  }

  walk_etc_pacfiles("/etc", 0, &found);

  if (found.count == 0) {
    printf(CLR_GREEN "[✓] No unmerged .pacnew / .pacsave files.\n" CLR_RESET);
  } else {
    qsort(found.items, found.count, sizeof(char *), cmp_cstr_ptr);
    printf(CLR_YELLOW "[!] Unmerged config files requiring review (%zu):\n"
                      CLR_RESET,
           found.count);
    for (size_t i = 0; i < found.count; i++) {
      printf("    - %s\n", found.items[i]);
      free(found.items[i]);
    }
  }
  free(found.items);
}

static const char *systemd_exit_tag(int status) {
  switch (status) {
  case 200:
    return "200/CHDIR";
  case 203:
    return "203/EXEC";
  case 217:
    return "217/USER";
  case 218:
    return "218/CAPABILITIES";
  case 219:
    return "219/CGROUP";
  case 226:
    return "226/NAMESPACE";
  default:
    return NULL;
  }
}

static int is_systemd_boilerplate_log(const char *line) {
  if (strncmp(line, "Started ", 8) == 0 || strncmp(line, "Starting ", 9) == 0 ||
      strncmp(line, "Stopped ", 8) == 0 || strncmp(line, "Stopping ", 9) == 0)
    return 1;
  if (strstr(line, ": Scheduled restart job") ||
      strstr(line, ": Main process exited,") ||
      strstr(line, ": Failed with result ") || strstr(line, ": Consumed ") ||
      strstr(line, ": Failed at step EXEC spawning "))
    return 1;
  return 0;
}

// Inspects each failing or crash-looping unit via `systemctl show` and
// `journalctl` to explain *why* it is failing and print a concrete fix hint.
static void trace_systemd_units(const char *list_buf, int is_user) {
  const char *scope_flag = is_user ? " --user" : "";
  const char *cur = list_buf;

  while (*cur != '\0') {
    const char *nl = strchr(cur, '\n');
    size_t llen = nl ? (size_t)(nl - cur) : strlen(cur);

    // Extract first whitespace-delimited token (unit name)
    const char *s = cur;
    const char *end = cur + llen;
    while (s < end && (*s == ' ' || *s == '\t' || *s == '*'))
      s++;
    const char *uend = s;
    while (uend < end && *uend != ' ' && *uend != '\t' && *uend != '\r')
      uend++;

    char unit[128];
    size_t ulen = (size_t)(uend - s);
    if (ulen > 0 && ulen < sizeof(unit)) {
      memcpy(unit, s, ulen);
      unit[ulen] = '\0';

      char prop_buf[4096];
      int rc = 0;
      if (is_user) {
        char *const cmd[] = {
            "systemctl",
            "--user",
            "show",
            unit,
            "-p",
            "FragmentPath,ActiveState,SubState,Result,ExecMainStatus,NRestarts,"
            "ExecStart",
            NULL};
        capture_cmd_output(cmd, prop_buf, sizeof(prop_buf), &rc);
      } else {
        char *const cmd[] = {
            "systemctl",
            "show",
            unit,
            "-p",
            "FragmentPath,ActiveState,SubState,Result,ExecMainStatus,NRestarts,"
            "ExecStart",
            NULL};
        capture_cmd_output(cmd, prop_buf, sizeof(prop_buf), &rc);
      }

      char frag[256] = "", active[32] = "", sub[32] = "", result[32] = "";
      char exec_path[256] = "";
      int exit_status = 0, restarts = 0;

      const char *lp = prop_buf;
      while (*lp != '\0') {
        const char *lnl = strchr(lp, '\n');
        size_t n = lnl ? (size_t)(lnl - lp) : strlen(lp);
        if (n > 0 && lp[n - 1] == '\r')
          n--;

        if (n > 13 && strncmp(lp, "FragmentPath=", 13) == 0)
          snprintf(frag, sizeof(frag), "%.*s", (int)(n - 13), lp + 13);
        else if (n > 12 && strncmp(lp, "ActiveState=", 12) == 0)
          snprintf(active, sizeof(active), "%.*s", (int)(n - 12), lp + 12);
        else if (n > 9 && strncmp(lp, "SubState=", 9) == 0)
          snprintf(sub, sizeof(sub), "%.*s", (int)(n - 9), lp + 9);
        else if (n > 7 && strncmp(lp, "Result=", 7) == 0)
          snprintf(result, sizeof(result), "%.*s", (int)(n - 7), lp + 7);
        else if (n > 15 && strncmp(lp, "ExecMainStatus=", 15) == 0)
          exit_status = atoi(lp + 15);
        else if (n > 10 && strncmp(lp, "NRestarts=", 10) == 0)
          restarts = atoi(lp + 10);
        else if (n > 10 && strncmp(lp, "ExecStart=", 10) == 0) {
          const char *path_key = strstr(lp + 10, "path=");
          if (path_key && path_key < lp + n) {
            path_key += 5;
            const char *pe = path_key;
            while (pe < lp + n && *pe != ' ' && *pe != ';')
              pe++;
            snprintf(exec_path, sizeof(exec_path), "%.*s",
                     (int)(pe - path_key), path_key);
          }
        }
        if (!lnl)
          break;
        lp = lnl + 1;
      }

      int exec_missing = (exec_path[0] == '/' && access(exec_path, F_OK) != 0);
      int exec_noexec =
          (!exec_missing && exec_path[0] == '/' && access(exec_path, X_OK) != 0);

      // Pull up to 2 distinct non-boilerplate error lines from journalctl
      char traces[2][256] = {"", ""};
      int trace_count = 0;
      int port_in_use = 0;
      if (have_cmd("journalctl")) {
        char jbuf[4096];
        int jrc = 0;
        if (is_user) {
          char *const jcmd[] = {"journalctl", "--user", "-b",        "-u",
                                unit,         "-n",     "12",        "-o",
                                "cat",        "--no-pager", NULL};
          capture_cmd_output(jcmd, jbuf, sizeof(jbuf), &jrc);
        } else {
          char *const jcmd[] = {"journalctl", "-b", "-u",         unit,
                                "-n",         "12", "-o",         "cat",
                                "--no-pager", NULL};
          capture_cmd_output(jcmd, jbuf, sizeof(jbuf), &jrc);
        }

        const char *jp = jbuf;
        while (*jp != '\0') {
          const char *jnl = strchr(jp, '\n');
          size_t jlen = jnl ? (size_t)(jnl - jp) : strlen(jp);
          if (jlen > 0 && jp[jlen - 1] == '\r')
            jlen--;

          char line[256];
          if (jlen > 0) {
            snprintf(line, sizeof(line), "%.*s", (int)jlen, jp);
            if (strstr(line, "address already in use") ||
                strstr(line, "EADDRINUSE"))
              port_in_use = 1;
            if (!is_systemd_boilerplate_log(line)) {
              int dup = 0;
              for (int t = 0; t < trace_count; t++) {
                if (strcmp(traces[t], line) == 0)
                  dup = 1;
              }
              if (!dup && trace_count < 2)
                snprintf(traces[trace_count++], sizeof(traces[0]), "%s", line);
            }
          }
          if (!jnl)
            break;
          jp = jnl + 1;
        }
      }

      // Check whether a user unit is colliding with an active system unit of
      // the same name (e.g. both user and system ollama.service enabled).
      int sys_twin_active = 0;
      if (is_user) {
        char dummy[64];
        int arc = -1;
        char *const acmd[] = {"systemctl", "is-active", "--quiet", unit, NULL};
        capture_cmd_output(acmd, dummy, sizeof(dummy), &arc);
        if (arc == 0)
          sys_twin_active = 1;
      }

      const char *stag = systemd_exit_tag(exit_status);
      char status_str[32];
      if (stag)
        snprintf(status_str, sizeof(status_str), "%s", stag);
      else
        snprintf(status_str, sizeof(status_str), "%d", exit_status);

      printf("    " CLR_YELLOW "*" CLR_RESET " " CLR_CYAN "%s" CLR_RESET
             " [%s/%s, result=%s, status=%s, restarts=%d]\n",
             unit, active[0] ? active : "?", sub[0] ? sub : "?",
             result[0] ? result : "?", status_str, restarts);
      if (frag[0])
        printf("      Unit : %s\n", frag);
      if (exec_path[0]) {
        if (exec_missing)
          printf("      Exec : %s " CLR_RED "(MISSING on disk!)" CLR_RESET "\n",
                 exec_path);
        else if (exec_noexec)
          printf("      Exec : %s " CLR_RED "(not executable!)" CLR_RESET "\n",
                 exec_path);
        else
          printf("      Exec : %s\n", exec_path);
      }
      for (int t = 0; t < trace_count; t++)
        printf("      Log  : %s\n", traces[t]);

      if (exit_status == 203 || exec_missing) {
        printf("      Why  : Target executable was uninstalled or moved, "
               "leaving an orphaned service.\n");
        printf("      Fix  : systemctl%s disable --now %s\n", scope_flag, unit);
      } else if (exec_noexec) {
        printf("      Why  : Target binary exists but lacks execute "
               "permissions.\n");
        printf("      Fix  : chmod +x %s\n", exec_path);
      } else if (exit_status == 200) {
        printf("      Why  : Configured WorkingDirectory no longer exists on "
               "disk.\n");
        printf("      Fix  : Edit %s or disable with: systemctl%s disable "
               "--now %s\n",
               frag[0] ? frag : unit, scope_flag, unit);
      } else if (sys_twin_active) {
        printf("      Why  : Duplicate unit — system-wide '%s' is already "
               "running%s.\n",
               unit, port_in_use ? " and holding the port" : "");
        printf("      Fix  : systemctl --user disable --now %s\n", unit);
      } else if (port_in_use) {
        printf("      Why  : Port/socket is already bound by another "
               "process.\n");
        printf("      Fix  : ss -tulpn   (or systemctl%s disable --now %s)\n",
               scope_flag, unit);
      } else if (strcmp(result, "core-dump") == 0) {
        printf("      Why  : Service process crashed with a signal/core "
               "dump.\n");
        printf("      Fix  : coredumpctl info %s\n", unit);
      } else {
        printf("      Fix  : journalctl%s -xeu %s\n", scope_flag, unit);
      }
    }

    if (!nl)
      break;
    cur = nl + 1;
  }
}

// Checks both system-wide and per-user systemd managers for failed units AND
// crash-looping (`activating / auto-restart`) units, printing a root-cause
// trace and actionable fix command for each unhealthy service.
static void check_systemd_health(void) {
  if (access("/run/systemd/system", F_OK) != 0 || !have_cmd("systemctl"))
    return;

  char *const sys_units[] = {
      "systemctl",  "list-units", "--state=failed,auto-restart",
      "--no-legend", "--plain",   "--no-pager",
      NULL};
  char buf[8192];
  int rc = 0;
  int healthy = 1;

  if (capture_cmd_output(sys_units, buf, sizeof(buf), &rc) > 0 &&
      buf[strspn(buf, " \t\r\n")] != '\0') {
    printf(CLR_YELLOW "[!] Failed or crash-looping system systemd units:\n"
                      CLR_RESET);
    trace_systemd_units(buf, 0);
    healthy = 0;
  }

  const char *xdg = getenv("XDG_RUNTIME_DIR");
  if (xdg && *xdg != '\0') {
    char *const usr_units[] = {"systemctl",
                               "--user",
                               "list-units",
                               "--state=failed,auto-restart",
                               "--no-legend",
                               "--plain",
                               "--no-pager",
                               NULL};
    if (capture_cmd_output(usr_units, buf, sizeof(buf), &rc) > 0 &&
        buf[strspn(buf, " \t\r\n")] != '\0') {
      printf(CLR_YELLOW "[!] Failed or crash-looping user systemd units:\n"
                        CLR_RESET);
      trace_systemd_units(buf, 1);
      healthy = 0;
    }
  }

  if (healthy) {
    printf(CLR_GREEN "[✓] All systemd system & user services healthy.\n"
                     CLR_RESET);
  }
}

static const char *sig_short_name(int sig) {
  switch (sig) {
  case 4:
    return "SIGILL";
  case 5:
    return "SIGTRAP";
  case 6:
    return "SIGABRT";
  case 7:
    return "SIGBUS";
  case 8:
    return "SIGFPE";
  case 11:
    return "SIGSEGV";
  case 31:
    return "SIGSYS";
  default:
    return NULL;
  }
}

// Summarizes any process coredumps recorded during the current boot via
// `coredumpctl --json=short`, deduplicating repeated crashes by executable +
// signal so silent background segfaults/aborts are surfaced cleanly.
static void check_boot_coredumps(void) {
  if (access("/run/systemd/system", F_OK) != 0 || !have_cmd("coredumpctl"))
    return;

  struct sysinfo si;
  if (sysinfo(&si) != 0)
    return;
  long long boot_ts = (long long)time(NULL) - (long long)si.uptime;
  if (boot_ts <= 0)
    return;

  char since_arg[64];
  snprintf(since_arg, sizeof(since_arg), "--since=@%lld", boot_ts);

  char buf[32768];
  int rc = -1;
  char *const cmd[] = {"coredumpctl", "list",         since_arg,
                       "--json=short", "--no-pager", NULL};
  if (capture_cmd_output(cmd, buf, sizeof(buf), &rc) <= 0 || rc != 0 ||
      buf[0] != '[') {
    printf(CLR_GREEN "[✓] No process coredumps recorded this boot.\n"
                     CLR_RESET);
    return;
  }

  struct crash_item {
    char exe[256];
    int sig;
    int last_pid;
    size_t count;
  } items[32];
  size_t item_count = 0;

  const char *obj_start = NULL;
  int depth = 0, in_str = 0;
  for (const char *p = buf; *p != '\0'; p++) {
    if (in_str) {
      if (*p == '\\' && *(p + 1) != '\0')
        p++;
      else if (*p == '"')
        in_str = 0;
      continue;
    }
    if (*p == '"') {
      in_str = 1;
      continue;
    }
    if (*p == '{') {
      if (depth == 0)
        obj_start = p;
      depth++;
    } else if (*p == '}') {
      depth--;
      if (depth == 0 && obj_start) {
        char exe[256] = "";
        extract_json_str(obj_start, p, "\"exe\":", exe, sizeof(exe));
        int sig = 0, pid = 0;
        const char *sp = strstr(obj_start, "\"sig\":");
        if (sp && sp < p)
          sig = atoi(sp + 6);
        const char *pp = strstr(obj_start, "\"pid\":");
        if (pp && pp < p)
          pid = atoi(pp + 6);

        if (exe[0] != '\0') {
          size_t idx = item_count;
          for (size_t i = 0; i < item_count; i++) {
            if (strcmp(items[i].exe, exe) == 0 && items[i].sig == sig) {
              idx = i;
              break;
            }
          }
          if (idx < item_count) {
            items[idx].count++;
            if (pid > 0)
              items[idx].last_pid = pid;
          } else if (item_count < 32) {
            snprintf(items[item_count].exe, sizeof(items[0].exe), "%s", exe);
            items[item_count].sig = sig;
            items[item_count].last_pid = pid;
            items[item_count].count = 1;
            item_count++;
          }
        }
        obj_start = NULL;
      }
    }
  }

  if (item_count == 0) {
    printf(CLR_GREEN "[✓] No process coredumps recorded this boot.\n"
                     CLR_RESET);
    return;
  }

  printf(CLR_YELLOW "[!] Process coredumps recorded this boot:\n" CLR_RESET);
  for (size_t i = 0; i < item_count; i++) {
    const char *sname = sig_short_name(items[i].sig);
    char sig_buf[24];
    if (sname)
      snprintf(sig_buf, sizeof(sig_buf), "%s", sname);
    else
      snprintf(sig_buf, sizeof(sig_buf), "SIG#%d", items[i].sig);

    const char *gone =
        (items[i].exe[0] == '/' && access(items[i].exe, F_OK) != 0)
            ? " [binary since removed]"
            : "";

    if (items[i].last_pid > 0) {
      printf("    - %s%s (%s, %zux) -> inspect: coredumpctl info %d\n",
             items[i].exe, gone, sig_buf, items[i].count, items[i].last_pid);
    } else {
      printf("    - %s%s (%s, %zux)\n", items[i].exe, gone, sig_buf,
             items[i].count);
    }
  }
}

static void walk_dangling_systemd_links(const char *dir, int depth,
                                        struct str_vec *out) {
  if (depth > 2)
    return;
  DIR *d = opendir(dir);
  if (!d)
    return;

  struct dirent *ent;
  while ((ent = readdir(d)) != NULL) {
    if (ent->d_name[0] == '.')
      continue;
    char path[PATH_MAX];
    if (snprintf(path, sizeof(path), "%s/%s", dir, ent->d_name) >=
        (int)sizeof(path))
      continue;

    struct stat lst, st;
    if (lstat(path, &lst) != 0)
      continue;
    if (S_ISDIR(lst.st_mode)) {
      walk_dangling_systemd_links(path, depth + 1, out);
    } else if (S_ISLNK(lst.st_mode)) {
      if (stat(path, &st) != 0 && errno == ENOENT) {
        char target[PATH_MAX];
        ssize_t tlen = readlink(path, target, sizeof(target) - 1);
        char msg[PATH_MAX * 2 + 16];
        if (tlen > 0) {
          target[tlen] = '\0';
          snprintf(msg, sizeof(msg), "%s -> %s", path, target);
        } else {
          snprintf(msg, sizeof(msg), "%s", path);
        }
        str_vec_add_unique(out, msg);
      }
    }
  }
  closedir(d);
}

// Audits three common configuration drift traps on Arch Linux:
//   1. Unmanaged binaries in /usr/local/bin or ~/.local/bin shadowing /usr/bin
//      packages (so pacman upgrades /usr/bin/<pkg> while PATH runs the old copy)
//   2. Full unit copies in /etc/systemd/system/*.service masking package units
//      in /usr/lib/systemd/system/ while pointing at /usr/local or missing bins
//   3. Dangling .wants/.requires symlinks left behind by removed services
static void check_shadowed_paths(void) {
  struct str_vec shadowed_bins = {NULL, 0, 0};
  const char *home = getenv("HOME");
  char user_bin[PATH_MAX] = "";
  if (home && home[0] == '/')
    snprintf(user_bin, sizeof(user_bin), "%s/.local/bin", home);

  const char *bin_dirs[2] = {"/usr/local/bin",
                             user_bin[0] ? user_bin : NULL};
  for (int d_idx = 0; d_idx < 2; d_idx++) {
    if (!bin_dirs[d_idx])
      continue;
    DIR *d = opendir(bin_dirs[d_idx]);
    if (!d)
      continue;
    struct dirent *ent;
    while ((ent = readdir(d)) != NULL) {
      if (ent->d_name[0] == '.')
        continue;
      char cand[PATH_MAX], sys_bin[PATH_MAX];
      if (snprintf(cand, sizeof(cand), "%s/%s", bin_dirs[d_idx], ent->d_name) >=
              (int)sizeof(cand) ||
          snprintf(sys_bin, sizeof(sys_bin), "/usr/bin/%s", ent->d_name) >=
              (int)sizeof(sys_bin))
        continue;
      if (access(cand, X_OK) != 0 || access(sys_bin, X_OK) != 0)
        continue;

      char real_cand[PATH_MAX], real_sys[PATH_MAX];
      if (realpath(cand, real_cand) && realpath(sys_bin, real_sys) &&
          strcmp(real_cand, real_sys) == 0)
        continue;

      char msg[PATH_MAX * 2 + 32];
      snprintf(msg, sizeof(msg), "%s  (shadows %s)", cand, sys_bin);
      str_vec_add_unique(&shadowed_bins, msg);
    }
    closedir(d);
  }

  struct str_vec shadowed_units = {NULL, 0, 0};
  DIR *etc_sd = opendir("/etc/systemd/system");
  if (etc_sd) {
    struct dirent *ent;
    while ((ent = readdir(etc_sd)) != NULL) {
      size_t nlen = strlen(ent->d_name);
      if (nlen <= 8 || strcmp(ent->d_name + nlen - 8, ".service") != 0)
        continue;

      char etc_path[PATH_MAX], lib_path[PATH_MAX];
      if (snprintf(etc_path, sizeof(etc_path), "/etc/systemd/system/%s",
                   ent->d_name) >= (int)sizeof(etc_path) ||
          snprintf(lib_path, sizeof(lib_path), "/usr/lib/systemd/system/%s",
                   ent->d_name) >= (int)sizeof(lib_path))
        continue;

      struct stat lst;
      if (lstat(etc_path, &lst) != 0 || !S_ISREG(lst.st_mode) ||
          access(lib_path, F_OK) != 0)
        continue;

      FILE *fp = fopen(etc_path, "r");
      if (!fp)
        continue;
      char line[512];
      while (fgets(line, sizeof(line), fp)) {
        char *p = line;
        while (*p == ' ' || *p == '\t')
          p++;
        if (strncmp(p, "ExecStart=", 10) == 0) {
          char *v = p + 10;
          while (*v == ' ' || *v == '\t' || *v == '-' || *v == '@' ||
                 *v == '+' || *v == '!' || *v == '"')
            v++;
          char exe[256];
          size_t ei = 0;
          while (*v != '\0' && *v != ' ' && *v != '\t' && *v != '"' &&
                 *v != '\r' && *v != '\n' && ei + 1 < sizeof(exe))
            exe[ei++] = *v++;
          exe[ei] = '\0';

          if (strncmp(exe, "/usr/local/", 11) == 0 ||
              (exe[0] == '/' && access(exe, F_OK) != 0)) {
            char msg[PATH_MAX * 2 + 320];
            snprintf(msg, sizeof(msg), "%s (runs %s%s, masks %s)", etc_path,
                     exe, (access(exe, F_OK) != 0) ? " [MISSING]" : "",
                     lib_path);
            str_vec_add_unique(&shadowed_units, msg);
            break;
          }
        }
      }
      fclose(fp);
    }
    closedir(etc_sd);
  }

  struct str_vec dangling_links = {NULL, 0, 0};
  walk_dangling_systemd_links("/etc/systemd/system", 0, &dangling_links);
  if (home && home[0] == '/') {
    char user_sd[PATH_MAX];
    if (snprintf(user_sd, sizeof(user_sd), "%s/.config/systemd/user", home) <
        (int)sizeof(user_sd))
      walk_dangling_systemd_links(user_sd, 0, &dangling_links);
  }

  if (shadowed_bins.count > 0) {
    qsort(shadowed_bins.items, shadowed_bins.count, sizeof(char *),
          cmp_cstr_ptr);
    printf(CLR_YELLOW "[!] Unmanaged binaries in PATH shadowing /usr/bin "
                      "packages (%zu):\n" CLR_RESET,
           shadowed_bins.count);
    for (size_t i = 0; i < shadowed_bins.count; i++) {
      printf("    - %s\n", shadowed_bins.items[i]);
      free(shadowed_bins.items[i]);
    }
  }
  free(shadowed_bins.items);

  if (shadowed_units.count > 0) {
    qsort(shadowed_units.items, shadowed_units.count, sizeof(char *),
          cmp_cstr_ptr);
    printf(CLR_YELLOW "[!] Custom /etc/systemd/system units masking package "
                      "units (%zu):\n" CLR_RESET,
           shadowed_units.count);
    for (size_t i = 0; i < shadowed_units.count; i++) {
      printf("    - %s\n", shadowed_units.items[i]);
      free(shadowed_units.items[i]);
    }
  }
  free(shadowed_units.items);

  if (dangling_links.count > 0) {
    qsort(dangling_links.items, dangling_links.count, sizeof(char *),
          cmp_cstr_ptr);
    printf(CLR_YELLOW "[!] Dangling systemd unit symlinks (%zu):\n" CLR_RESET,
           dangling_links.count);
    for (size_t i = 0; i < dangling_links.count; i++) {
      printf("    - %s\n", dangling_links.items[i]);
      free(dangling_links.items[i]);
    }
  }
  free(dangling_links.items);
}

static size_t count_subdirs(const char *dir) {
  DIR *d = opendir(dir);
  if (!d)
    return 0;
  size_t n = 0;
  struct dirent *ent;
  while ((ent = readdir(d)) != NULL) {
    if (ent->d_name[0] != '.')
      n++;
  }
  closedir(d);
  return n;
}

// Built-in native C system summary card (replaces external `fastfetch`)
static void print_sys_summary(void) {
  struct utsname uts;
  if (uname(&uts) != 0)
    return;

  const char *user = "user";
  struct passwd *pw = getpwuid(getuid());
  if (pw && pw->pw_name && *pw->pw_name)
    user = pw->pw_name;

  // OS name from /etc/os-release
  char os_name[256] = "Arch Linux";
  FILE *os_fp = fopen("/etc/os-release", "r");
  if (os_fp) {
    char line[256];
    while (fgets(line, sizeof(line), os_fp)) {
      if (strncmp(line, "PRETTY_NAME=", 12) == 0) {
        char *v = line + 12;
        v[strcspn(v, "\r\n")] = '\0';
        if (*v == '"') {
          v++;
          size_t l = strlen(v);
          if (l > 0 && v[l - 1] == '"')
            v[l - 1] = '\0';
        }
        if (*v != '\0')
          snprintf(os_name, sizeof(os_name), "%s", v);
        break;
      }
    }
    fclose(os_fp);
  }

  // CPU model from /proc/cpuinfo
  char cpu_model[256] = "Unknown CPU";
  FILE *cpu_fp = fopen("/proc/cpuinfo", "r");
  if (cpu_fp) {
    char line[256];
    while (fgets(line, sizeof(line), cpu_fp)) {
      if (strncmp(line, "model name", 10) == 0 ||
          strncmp(line, "Model", 5) == 0) {
        char *colon = strchr(line, ':');
        if (colon) {
          colon++;
          while (*colon == ' ' || *colon == '\t')
            colon++;
          colon[strcspn(colon, "\r\n")] = '\0';
          if (*colon != '\0') {
            snprintf(cpu_model, sizeof(cpu_model), "%s", colon);
            break;
          }
        }
      }
    }
    fclose(cpu_fp);
  }
  long threads = sysconf(_SC_NPROCESSORS_ONLN);

  // Memory usage from /proc/meminfo
  unsigned long long mem_total_kb = 0, mem_avail_kb = 0;
  FILE *mem_fp = fopen("/proc/meminfo", "r");
  if (mem_fp) {
    char line[128];
    while (fgets(line, sizeof(line), mem_fp)) {
      sscanf(line, "MemTotal: %llu kB", &mem_total_kb);
      sscanf(line, "MemAvailable: %llu kB", &mem_avail_kb);
      if (mem_total_kb && mem_avail_kb)
        break;
    }
    fclose(mem_fp);
  }

  // Uptime & load average via sysinfo()
  struct sysinfo si;
  long up_s = (sysinfo(&si) == 0) ? si.uptime : 0;
  long days = up_s / 86400;
  long hrs = (up_s % 86400) / 3600;
  long mins = (up_s % 3600) / 60;
  double load1 = (double)si.loads[0] / (double)(1 << SI_LOAD_SHIFT);
  double load5 = (double)si.loads[1] / (double)(1 << SI_LOAD_SHIFT);

  // Package counts + installed size (pacman via libalpm + Flatpak app dirs)
  size_t pacman_pkgs = 0;
  off_t pacman_bytes = 0;
  alpm_errno_t err;
  alpm_handle_t *handle = alpm_initialize("/", "/var/lib/pacman", &err);
  if (handle) {
    for (alpm_list_t *i = alpm_db_get_pkgcache(alpm_get_localdb(handle));
         i != NULL; i = alpm_list_next(i)) {
      pacman_pkgs++;
      pacman_bytes += alpm_pkg_get_isize(i->data);
    }
    alpm_release(handle);
  }
  size_t flatpak_pkgs = count_subdirs("/var/lib/flatpak/app");
  const char *home = getenv("HOME");
  if (home && *home) {
    char ufp[PATH_MAX];
    if (snprintf(ufp, sizeof(ufp), "%s/.local/share/flatpak/app", home) <
        (int)sizeof(ufp))
      flatpak_pkgs += count_subdirs(ufp);
  }

  printf("\n" CLR_CYAN "   %s@%s" CLR_RESET "\n   ", user, uts.nodename);
  size_t hlen = strlen(user) + 1 + strlen(uts.nodename);
  for (size_t i = 0; i < hlen && i < 60; i++)
    putchar('-');
  putchar('\n');

  printf("   " CLR_CYAN "%-10s" CLR_RESET " %s (%s)\n", "OS", os_name,
         uts.machine);
  printf("   " CLR_CYAN "%-10s" CLR_RESET " %s\n", "Kernel", uts.release);
  if (days > 0) {
    printf("   " CLR_CYAN "%-10s" CLR_RESET
           " %ldd %ldh %ldm (load %.2f, %.2f)\n",
           "Uptime", days, hrs, mins, load1, load5);
  } else {
    printf("   " CLR_CYAN "%-10s" CLR_RESET " %ldh %ldm (load %.2f, %.2f)\n",
           "Uptime", hrs, mins, load1, load5);
  }
  if (threads > 0)
    printf("   " CLR_CYAN "%-10s" CLR_RESET " %s (%ld threads)\n", "CPU",
           cpu_model, threads);
  else
    printf("   " CLR_CYAN "%-10s" CLR_RESET " %s\n", "CPU", cpu_model);

  if (mem_total_kb > 0) {
    double tot = (double)mem_total_kb / (1024.0 * 1024.0);
    double used = (double)(mem_total_kb - mem_avail_kb) / (1024.0 * 1024.0);
    printf("   " CLR_CYAN "%-10s" CLR_RESET " %.2f / %.2f GiB (%.0f%%)\n",
           "Memory", used, tot, (used / tot) * 100.0);
  }

  struct statvfs vfs;
  if (statvfs("/", &vfs) == 0 && vfs.f_blocks > 0) {
    double tot =
        ((double)vfs.f_blocks * (double)vfs.f_frsize) / (1024.0 * 1024.0 * 1024.0);
    double avail =
        ((double)vfs.f_bavail * (double)vfs.f_frsize) / (1024.0 * 1024.0 * 1024.0);
    double used = tot -
                  ((double)vfs.f_bfree * (double)vfs.f_frsize) /
                      (1024.0 * 1024.0 * 1024.0);
    printf("   " CLR_CYAN "%-10s" CLR_RESET
           " %.2f / %.2f GiB used (%.2f GiB free)\n",
           "Disk (/)", used, tot, avail);
  }

  double pkg_gib = (double)pacman_bytes / (1024.0 * 1024.0 * 1024.0);
  if (flatpak_pkgs > 0) {
    printf("   " CLR_CYAN "%-10s" CLR_RESET
           " %zu (pacman, %.2f GiB), %zu (flatpak)\n",
           "Packages", pacman_pkgs, pkg_gib, flatpak_pkgs);
  } else {
    printf("   " CLR_CYAN "%-10s" CLR_RESET " %zu (pacman, %.2f GiB)\n",
           "Packages", pacman_pkgs, pkg_gib);
  }
}

// Prints a numbered pipeline stage header, e.g. ":: [2/6] Updating ..."
static void print_step(int *step, int total, const char *msg) {
  printf(CLR_CYAN "\n:: [%d/%d] %s\n" CLR_RESET, ++*step, total, msg);
}

static void usage(const char *prog) {
  printf("Usage: %s [options]\n"
         "Zero-extra-dependency Arch Linux maintenance: official repos + AUR +\n"
         "Flatpak + Snap upgrades, native cache/orphan cleanup, and health "
         "checks.\n\n"
         "  -c, --check   Read-only update, package DB, service, boot & kernel "
         "health report\n"
         "  -y, --yes     Unattended: auto-confirm every package manager "
         "prompt\n"
         "  -h, --help    Show this help\n\n"
         "Run as your normal user; sudo is requested once and kept alive.\n",
         prog);
}

int main(int argc, char *argv[]) {
  int check_only = 0;
  int auto_yes = 0;
  int stale_libs_only = 0;
  int clean_cache_only = 0;
  int scan_pacnew_only = 0;

  // Parse CLI flags:
  //   -c, --check   : Run read-only update + package/system health checks
  //   -y, --yes     : Auto-confirm yay/paru/pacman/flatpak prompts (unattended)
  //   -h, --help    : Show usage
  //   --clean-cache : Internal root helper for native pacman cache trimming
  //   --scan-pacnew : Internal root helper for full /etc .pacnew/.pacsave scan
  //   --stale-libs  : Internal root helper for system-wide /proc stale binary
  //                   and library scan
  for (int i = 1; i < argc; i++) {
    if (strcmp(argv[i], "-c") == 0 || strcmp(argv[i], "--check") == 0)
      check_only = 1;
    else if (strcmp(argv[i], "-y") == 0 || strcmp(argv[i], "--yes") == 0)
      auto_yes = 1;
    else if (strcmp(argv[i], "--stale-libs") == 0)
      stale_libs_only = 1;
    else if (strcmp(argv[i], "--clean-cache") == 0)
      clean_cache_only = 1;
    else if (strcmp(argv[i], "--scan-pacnew") == 0)
      scan_pacnew_only = 1;
    else if (strcmp(argv[i], "-h") == 0 || strcmp(argv[i], "--help") == 0) {
      usage(argv[0]);
      return EXIT_SUCCESS;
    } else {
      fprintf(stderr, CLR_RED ":: Unknown option '%s'\n\n" CLR_RESET, argv[i]);
      usage(argv[0]);
      return EXIT_FAILURE;
    }
  }

  if (stale_libs_only) {
    check_stale_libs();
    return EXIT_SUCCESS;
  }
  if (clean_cache_only) {
    clean_pacman_cache();
    return EXIT_SUCCESS;
  }
  if (scan_pacnew_only) {
    scan_pacnew_files();
    return EXIT_SUCCESS;
  }

  // Refuse to run full upgrade as root because yay/paru/makepkg must run as a
  // normal user and elevate via sudo only when installing packages.
  if (!check_only && geteuid() == 0) {
    fprintf(stderr,
            CLR_RED ":: Error: Run as normal user, not root.\n" CLR_RESET);
    return EXIT_FAILURE;
  }

  // Detect optional package managers (everything else is built in natively)
  const char *aur_helper =
      have_cmd("yay") ? "yay" : (have_cmd("paru") ? "paru" : NULL);

  run_alpm_telemetry(check_only, aur_helper != NULL);

  if (check_only) {
    printf("\n");
    check_package_database();
    check_dkms_status();
    scan_pacnew_files();
    check_shadowed_paths();
    check_boot_mounts(1);
    check_systemd_health();
    check_boot_coredumps();
    check_boot_performance();
    check_kernel_reboot();
    check_stale_libs();
    return EXIT_SUCCESS;
  }

  // Ensure no other pacman/yay instance holds the database lock
  if (access("/var/lib/pacman/db.lck", F_OK) == 0) {
    fprintf(stderr, CLR_RED ":: Error: /var/lib/pacman/db.lck exists!\n"
                            "   Another package manager is running (or "
                            "crashed). Clear it first.\n" CLR_RESET);
    return EXIT_FAILURE;
  }

  // Pre-flight storage & boot/ESP mount check before touching packages
  printf("\n");
  if (check_disk_space("/", MIN_FREE_GIB) != 0 ||
      check_disk_space("/var/cache/pacman/pkg", MIN_FREE_GIB) != 0 ||
      check_boot_mounts(0) != 0) {
    return EXIT_FAILURE;
  }

  int has_flatpak = have_cmd("flatpak");
  int has_snap = have_cmd("snap");
  int total_steps = 6 + has_flatpak + has_snap;
  int step = 0;

  if (!have_cmd("sudo")) {
    fprintf(stderr, CLR_RED ":: Error: sudo not found in PATH.\n" CLR_RESET);
    return EXIT_FAILURE;
  }
  if (acquire_sudo() != 0) {
    fprintf(stderr,
            CLR_RED ":: Error: Could not obtain sudo privileges.\n" CLR_RESET);
    return EXIT_FAILURE;
  }

  struct timespec t_start, t_end;
  clock_gettime(CLOCK_MONOTONIC, &t_start);

  char self_exe[PATH_MAX];
  ssize_t self_len = readlink("/proc/self/exe", self_exe, sizeof(self_exe) - 1);
  if (self_len > 0)
    self_exe[self_len] = '\0';

  // NULL here simply terminates the argv early when not running with -y.
  // With -y, `--ask=4` (ALPM_QUESTION_CONFLICT_PKG) lets pacman/yay/paru
  // swap conflicting/replaced packages atomically inside the transaction
  // instead of aborting on `--noconfirm`'s default "No".
  char *noconfirm = auto_yes ? "--noconfirm" : NULL;
  char *ask_conflict = auto_yes ? "--ask=4" : NULL;
  char *fp_yes = auto_yes ? "-y" : NULL;

  char *const up_aur[] = {(char *)aur_helper, "-Syu", noconfirm, ask_conflict,
                          NULL};
  char *const up_aur_ask[] = {(char *)aur_helper, "-Syu", NULL};
  char *const up_pacman[] = {"sudo",    "pacman",     "-Syu",
                             noconfirm, ask_conflict, NULL};
  char *const up_pacman_ask[] = {"sudo", "pacman", "-Syu", NULL};
  char *const fp_sys_up[] = {"sudo",     "flatpak", "update",
                             "--system", fp_yes,    NULL};
  char *const fp_usr_up[] = {"flatpak", "update", "--user", fp_yes, NULL};
  char *const fp_sys_cln[] = {"sudo",     "flatpak",  "uninstall",
                              "--system", "--unused", fp_yes,
                              NULL};
  char *const fp_usr_cln[] = {"flatpak",  "uninstall", "--user",
                              "--unused", fp_yes,      NULL};
  char *const snap_up[] = {"sudo", "snap", "refresh", NULL};

  if (aur_helper) {
    print_step(&step, total_steps,
               "Synchronizing & upgrading packages (Repo + AUR)...");
    int rc = run_cmd(up_aur);
    if (rc == -1 && auto_yes && isatty(STDIN_FILENO) &&
        access("/var/lib/pacman/db.lck", F_OK) != 0) {
      printf(CLR_YELLOW "\n:: Unattended upgrade hit an unresolved conflict — "
                        "retrying interactively...\n" CLR_RESET);
      rc = run_cmd(up_aur_ask);
    }
    if (rc != 0) {
      fprintf(stderr, CLR_RED ":: Upgrade failed or cancelled.\n" CLR_RESET);
      return EXIT_FAILURE;
    }
  } else {
    print_step(&step, total_steps,
               "Synchronizing & upgrading packages (Repo only; no yay/paru "
               "found for AUR)...");
    int rc = run_cmd(up_pacman);
    if (rc == -1 && auto_yes && isatty(STDIN_FILENO) &&
        access("/var/lib/pacman/db.lck", F_OK) != 0) {
      printf(CLR_YELLOW "\n:: Unattended upgrade hit an unresolved conflict — "
                        "retrying interactively...\n" CLR_RESET);
      rc = run_cmd(up_pacman_ask);
    }
    if (rc != 0) {
      fprintf(stderr, CLR_RED ":: Upgrade failed or cancelled.\n" CLR_RESET);
      return EXIT_FAILURE;
    }
  }

  if (has_flatpak) {
    print_step(&step, total_steps, "Updating Flatpak apps & runtimes...");
    if (run_cmd(fp_sys_up) != 0 || run_cmd(fp_usr_up) != 0)
      fprintf(stderr,
              CLR_YELLOW ":: Warning: Flatpak update reported errors.\n"
                         CLR_RESET);
  }

  if (has_snap) {
    print_step(&step, total_steps, "Refreshing Snap packages...");
    if (run_cmd(snap_up) != 0)
      fprintf(stderr,
              CLR_YELLOW ":: Warning: snap refresh reported errors.\n"
                         CLR_RESET);
  }

  print_step(&step, total_steps, "Verifying package database consistency...");
  check_package_database();
  check_dkms_status();

  print_step(&step, total_steps, "Sweeping orphaned dependencies...");
  sweep_orphans(aur_helper, auto_yes);

  print_step(&step, total_steps,
             has_flatpak ? "Cleaning caches (pacman/AUR: keep last 2 versions, "
                           "drop uninstalled; unused Flatpak runtimes)..."
                         : "Cleaning caches (pacman/AUR: keep last 2 versions, "
                           "drop uninstalled)...");
  if (self_len > 0) {
    char *const sudo_cache[] = {"sudo", self_exe, "--clean-cache", NULL};
    if (run_cmd(sudo_cache) != 0)
      clean_pacman_cache();
  } else {
    clean_pacman_cache();
  }
  clean_aur_cache();
  if (has_flatpak) {
    run_cmd(fp_sys_cln);
    run_cmd(fp_usr_cln);
  }

  print_step(&step, total_steps,
             "Scanning for unmerged .pacnew / .pacsave & shadowed paths...");
  if (self_len > 0) {
    char *const sudo_pacnew[] = {"sudo", self_exe, "--scan-pacnew", NULL};
    if (run_cmd(sudo_pacnew) != 0)
      scan_pacnew_files();
  } else {
    scan_pacnew_files();
  }
  check_shadowed_paths();

  print_step(&step, total_steps,
             "Checking systemd system & user service health...");
  check_systemd_health();
  check_boot_coredumps();
  check_boot_performance();

  print_sys_summary();

  check_kernel_reboot();

  // Re-run the stale binary/library scan as root so system daemons (sshd,
  // systemd-*, dbus, ...) are covered too.
  int scanned_as_root = 0;
  if (self_len > 0) {
    char *const sudo_scan[] = {"sudo", self_exe, "--stale-libs", NULL};
    scanned_as_root = (run_cmd(sudo_scan) == 0);
  }
  if (!scanned_as_root)
    check_stale_libs();

  clock_gettime(CLOCK_MONOTONIC, &t_end);
  double elapsed =
      (t_end.tv_sec - t_start.tv_sec) + (t_end.tv_nsec - t_start.tv_nsec) / 1e9;
  printf(CLR_YELLOW "\n:: Total maintenance time: %.2f seconds.\n" CLR_RESET,
         elapsed);

  return EXIT_SUCCESS;
}

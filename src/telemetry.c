#include "upgrade.h"

// Inspects /var/lib/pacman/db.lck. If present, reads the PID from the lockfile
// and checks /proc/<pid>/comm to distinguish an active package manager from a
// stale lock left behind by a crash or power loss.
// Returns 0 if unlocked, -1 if locked.
int check_pacman_lock(int check_only) {
  if (access("/var/lib/pacman/db.lck", F_OK) != 0)
    return 0;

  char pid_buf[32] = "";
  long lock_pid = 0;
  if (read_small_file("/var/lib/pacman/db.lck", pid_buf, sizeof(pid_buf)) == 0)
    lock_pid = strtol(pid_buf, NULL, 10);

  char comm[64] = "";
  int alive = 0;
  if (lock_pid > 0) {
    char proc_comm[64];
    snprintf(proc_comm, sizeof(proc_comm), "/proc/%ld/comm", lock_pid);
    if (read_small_file(proc_comm, comm, sizeof(comm)) == 0) {
      alive = 1;
    } else if (kill((pid_t)lock_pid, 0) == 0 || errno == EPERM) {
      alive = 1;
      snprintf(comm, sizeof(comm), "process");
    }
  }

  FILE *out = check_only ? stdout : stderr;
  if (alive) {
    fprintf(out,
            CLR_RED "[!] Pacman database is locked by active %s (PID %ld).\n"
                    "    Wait for it to finish before upgrading.\n" CLR_RESET,
            comm[0] ? comm : "process", lock_pid);
  } else if (lock_pid > 0) {
    fprintf(out,
            CLR_RED "[!] Stale /var/lib/pacman/db.lck detected (PID %ld is no "
                    "longer running).\n"
                    "    Clear it with: sudo rm -f /var/lib/pacman/db.lck\n"
                    CLR_RESET,
            lock_pid);
  } else {
    fprintf(out,
            CLR_RED "[!] /var/lib/pacman/db.lck exists!\n"
                    "    If no package manager is running, clear it with: "
                    "sudo rm -f /var/lib/pacman/db.lck\n" CLR_RESET);
  }
  return -1;
}

// Verifies that the pacman GnuPG keyring is initialized and populated on disk.
void check_pacman_keyring(void) {
  struct stat st;
  if (stat("/etc/pacman.d/gnupg/pubring.gpg", &st) != 0 &&
      stat("/etc/pacman.d/gnupg/pubring.kbx", &st) != 0) {
    if (errno == EACCES)
      return; // Unprivileged user on restricted /etc/pacman.d/gnupg
    printf(CLR_RED "[!] Pacman GPG keyring is missing or uninitialized!\n"
                   "    Fix: sudo pacman-key --init && sudo pacman-key "
                   "--populate\n" CLR_RESET);
    return;
  }
  if (st.st_size < 64) {
    printf(CLR_YELLOW "[!] Pacman GPG public keyring appears empty (%lld B).\n"
                      "    Fix: sudo pacman-key --populate\n" CLR_RESET,
           (long long)st.st_size);
  }
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
  curl_easy_setopt(curl, CURLOPT_USERAGENT, "upgrade-alpm/3.0");
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
  curl_easy_setopt(curl, CURLOPT_USERAGENT, "upgrade-alpm/3.0");
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

static int is_keyring_pkg(const char *name) {
  size_t len = strlen(name);
  return (len > 8 && strcmp(name + len - 8, "-keyring") == 0);
}

// In read-only check mode (`check_only == 1`), refreshes sync DBs into a
// private user-owned dbpath, compares repo + AUR versions, and checks Arch
// News. During a full upgrade (`check_only == 0`), avoids duplicating the
// sync DB download (and AUR RPC query when yay/paru is present) since step [1]
// immediately runs `-Syu`.
void run_alpm_telemetry(int check_only, int has_aur_helper,
                        int *keyring_needs_update) {
  if (keyring_needs_update)
    *keyring_needs_update = 0;

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
    } else {
      const char *sync_ver = alpm_pkg_get_version(sync_pkg);
      if (alpm_pkg_vercmp(sync_ver, local_ver) > 0 &&
          !alpm_pkg_should_ignore(handle, local_pkg)) {
        if (is_keyring_pkg(name) && keyring_needs_update)
          *keyring_needs_update = 1;
        if (check_only) {
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

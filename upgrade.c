#define _DEFAULT_SOURCE
#include <alpm.h>
#include <alpm_list.h>
#include <ctype.h>
#include <curl/curl.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/prctl.h>
#include <sys/stat.h>
#include <sys/statvfs.h>
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
  uint8_t in_aur; // Set to 1 once confirmed present in AUR RPC results
  uint8_t ignored; // Set to 1 if matched by IgnorePkg/IgnoreGroup
};

// Forks and executes an external command, waiting for it to finish.
// Retries waitpid() if interrupted by a signal (EINTR).
// Returns 0 if the child exited cleanly with status 0, or -1 on error/failure.
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
  return (WIFEXITED(status) && WEXITSTATUS(status) == 0) ? 0 : -1;
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
  curl_easy_setopt(curl, CURLOPT_USERAGENT, "upgrade-alpm/2.4");
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

            for (size_t i = batch_start; i < batch_end; i++) {
              if (strcmp(pkgs[i].name, pkg_name) == 0) {
                pkgs[i].in_aur = 1;
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

// Walks the local pacman database via libalpm to:
//   1. Count total installed packages and cumulative installed size on disk.
//   2. Compare installed repo packages against local sync DBs for updates.
//   3. Collect foreign packages (not in any sync DB) and query AUR RPC v5.
static void run_alpm_telemetry(void) {
  struct timespec t0, t1;
  clock_gettime(CLOCK_MONOTONIC, &t0);

  alpm_errno_t err;
  // Prefer a private dbpath whose sync DBs we can refresh without root;
  // fall back to the (possibly stale) system DBs if it can't be set up.
  char tmp_dbpath[PATH_MAX];
  int fresh = (prepare_tmp_dbpath(tmp_dbpath, sizeof(tmp_dbpath)) == 0);
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
      foreign_count++;
    } else {
      // Official repo package -> compare cached sync DB version vs installed
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

  // Audit all collected foreign packages against the live AUR RPC v5 API
  size_t aur_updates = 0;
  if (foreign_count > 0) {
    curl_global_init(CURL_GLOBAL_DEFAULT);
    CURL *curl = curl_easy_init();
    if (curl) {
      aur_updates = audit_aur_packages(curl, foreign, foreign_count);
      curl_easy_cleanup(curl);
    }
    curl_global_cleanup();
  }

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

// Scans /proc/<pid>/maps for processes readable by the current user that still
// have deleted shared libraries (/usr/lib/*.so ... (deleted)) mapped in RAM
// after an upgrade, deduplicating output by process name (/proc/<pid>/comm).
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

    char maps_path[64];
    snprintf(maps_path, sizeof(maps_path), "/proc/%d/maps", (int)pid);

    FILE *fp = fopen(maps_path, "r");
    if (!fp) {
      if (errno == EACCES)
        hidden++;
      continue;
    }

    char line[1024];
    char deleted_lib[256] = "";

    while (fgets(line, sizeof(line), fp)) {
      const char *usr_lib = strstr(line, "/usr/lib/");
      if (usr_lib && strstr(usr_lib, ".so") && strstr(usr_lib, "(deleted)")) {
        snprintf(deleted_lib, sizeof(deleted_lib), "%s", usr_lib);
        deleted_lib[strcspn(deleted_lib, " \t\n")] = '\0';
        break;
      }
    }
    fclose(fp);

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
        printf(CLR_YELLOW "\n[!] %s processes holding deleted /usr/lib "
                          "shared libraries in RAM:\n" CLR_RESET,
               as_root ? "All" : "User");
      }
      printf("    - %-18s (PID %-6d) -> %s\n", comm, (int)pid, deleted_lib);
      stale_count++;
    }
  }
  closedir(proc);

  if (stale_count == 0) {
    printf(CLR_GREEN "[✓] No %sprocesses holding stale /usr/lib shared "
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

// pacman-only fallback for orphan removal (no yay/paru installed):
// equivalent of `pacman -Qdtq | sudo pacman -Rns [--noconfirm] -`
static void remove_orphans_pacman(int auto_yes) {
  FILE *fp = popen("pacman -Qdtq 2>/dev/null", "r");
  if (!fp)
    return;

  size_t cap = 16, n = 0;
  char **args = malloc(cap * sizeof(char *));
  if (!args) {
    pclose(fp);
    return;
  }
  args[n++] = (char *)"sudo";
  args[n++] = (char *)"pacman";
  args[n++] = (char *)"-Rns";
  if (auto_yes)
    args[n++] = (char *)"--noconfirm";
  const size_t fixed = n;

  char line[256];
  while (fgets(line, sizeof(line), fp)) {
    line[strcspn(line, "\r\n")] = '\0';
    if (line[0] == '\0')
      continue;
    if (n + 2 > cap) { // Room for this name plus the NULL terminator
      char **tmp = realloc(args, cap * 2 * sizeof(char *));
      if (!tmp)
        break;
      args = tmp;
      cap *= 2;
    }
    if (!(args[n] = strdup(line)))
      break;
    n++;
  }
  pclose(fp);

  if (n == fixed) {
    printf(CLR_GREEN "[✓] No orphaned packages.\n" CLR_RESET);
  } else {
    args[n] = NULL;
    run_cmd(args);
  }

  for (size_t i = fixed; i < n; i++)
    free(args[i]);
  free(args);
}

// Prints a numbered pipeline stage header, e.g. ":: [2/6] Updating ..."
static void print_step(int *step, int total, const char *msg) {
  printf(CLR_CYAN "\n:: [%d/%d] %s\n" CLR_RESET, ++*step, total, msg);
}

static void usage(const char *prog) {
  printf("Usage: %s [options]\n"
         "One-stop Arch Linux maintenance: official repos + AUR (yay/paru) +\n"
         "Flatpak + Snap upgrades, then orphan/cache cleanup and health "
         "checks.\n\n"
         "  -c, --check   Read-only report of pending repo/AUR updates "
         "(no root needed)\n"
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

  // Parse CLI flags:
  //   -c, --check : Run read-only ALPM + AUR telemetry and exit
  //   -y, --yes   : Auto-confirm yay/paru/pacman/flatpak prompts (unattended)
  //   -h, --help  : Show usage
  //   --stale-libs: Only scan /proc for deleted shared libs (used internally
  //                 via sudo so root-owned daemons are covered too)
  for (int i = 1; i < argc; i++) {
    if (strcmp(argv[i], "-c") == 0 || strcmp(argv[i], "--check") == 0)
      check_only = 1;
    else if (strcmp(argv[i], "-y") == 0 || strcmp(argv[i], "--yes") == 0)
      auto_yes = 1;
    else if (strcmp(argv[i], "--stale-libs") == 0)
      stale_libs_only = 1;
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

  // Refuse to run full upgrade as root because yay/paru/makepkg must run as a
  // normal user and elevate via sudo only when installing packages.
  if (!check_only && geteuid() == 0) {
    fprintf(stderr,
            CLR_RED ":: Error: Run as normal user, not root.\n" CLR_RESET);
    return EXIT_FAILURE;
  }

  run_alpm_telemetry();

  if (check_only) {
    return EXIT_SUCCESS;
  }

  // Ensure no other pacman/yay instance holds the database lock
  if (access("/var/lib/pacman/db.lck", F_OK) == 0) {
    fprintf(stderr, CLR_RED ":: Error: /var/lib/pacman/db.lck exists!\n"
                            "   Another package manager is running (or "
                            "crashed). Clear it first.\n" CLR_RESET);
    return EXIT_FAILURE;
  }

  // Pre-flight storage check on root, pacman package cache, and /boot
  printf("\n");
  if (check_disk_space("/", MIN_FREE_GIB) != 0 ||
      check_disk_space("/var/cache/pacman/pkg", MIN_FREE_GIB) != 0 ||
      check_disk_space("/boot", 0.15) != 0) {
    return EXIT_FAILURE;
  }

  // Detect which package managers/tools this system actually has, so the
  // same binary works on any Arch-based install
  const char *aur_helper =
      have_cmd("yay") ? "yay" : (have_cmd("paru") ? "paru" : NULL);
  int has_flatpak = have_cmd("flatpak");
  int has_snap = have_cmd("snap");
  int has_paccache = have_cmd("paccache"); // pacman-contrib
  int has_pacdiff = have_cmd("pacdiff");   // pacman-contrib
  int total_steps = 4 + has_flatpak + has_snap + has_pacdiff;
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

  // NULL here simply terminates the argv early when not running with -y
  char *noconfirm = auto_yes ? "--noconfirm" : NULL;
  char *fp_yes = auto_yes ? "-y" : NULL;

  char *const up_aur[] = {(char *)aur_helper, "-Syu", noconfirm, NULL};
  char *const up_pacman[] = {"sudo", "pacman", "-Syu", noconfirm, NULL};
  char *const cln_yay[] = {"yay", "-Yc", noconfirm, NULL};
  char *const cln_paru[] = {"paru", "-c", noconfirm, NULL};
  char *const fp_sys_up[] = {"sudo",     "flatpak", "update",
                             "--system", fp_yes,    NULL};
  char *const fp_usr_up[] = {"flatpak", "update", "--user", fp_yes, NULL};
  char *const fp_sys_cln[] = {"sudo",     "flatpak",  "uninstall",
                              "--system", "--unused", fp_yes,
                              NULL};
  char *const fp_usr_cln[] = {"flatpak",  "uninstall", "--user",
                              "--unused", fp_yes,      NULL};
  char *const snap_up[] = {"sudo", "snap", "refresh", NULL};
  char *const paccache[] = {"sudo", "paccache", "-rk2", NULL};
  char *const paccache_un[] = {"sudo", "paccache", "-ruk0", NULL};
  char *const pacdiff[] = {"pacdiff", "-o", NULL};
  char *const sysok[] = {"systemctl", "is-system-running", "--quiet", NULL};
  char *const sysfail[] = {"systemctl", "--failed", "--no-legend", "--plain",
                           NULL};
  char *const fetch[] = {"fastfetch", NULL};

  if (aur_helper) {
    print_step(&step, total_steps,
               "Synchronizing & upgrading packages (Repo + AUR)...");
    if (run_cmd(up_aur) != 0) {
      fprintf(stderr, CLR_RED ":: Upgrade failed or cancelled.\n" CLR_RESET);
      return EXIT_FAILURE;
    }
  } else {
    print_step(&step, total_steps,
               "Synchronizing & upgrading packages (Repo only; no yay/paru "
               "found for AUR)...");
    if (run_cmd(up_pacman) != 0) {
      fprintf(stderr, CLR_RED ":: Upgrade failed or cancelled.\n" CLR_RESET);
      return EXIT_FAILURE;
    }
  }

  sync();

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

  print_step(&step, total_steps, "Sweeping orphaned dependencies...");
  if (aur_helper && strcmp(aur_helper, "yay") == 0)
    run_cmd(cln_yay);
  else if (aur_helper)
    run_cmd(cln_paru);
  else
    remove_orphans_pacman(auto_yes);

  print_step(&step, total_steps,
             has_flatpak ? "Cleaning caches (pacman: keep last 2 versions, "
                           "drop uninstalled; unused Flatpak runtimes)..."
                         : "Cleaning caches (pacman: keep last 2 versions, "
                           "drop uninstalled)...");
  if (has_paccache) {
    run_cmd(paccache);
    run_cmd(paccache_un);
  } else {
    printf(CLR_MAGENTA "    paccache not found — install 'pacman-contrib' to "
                       "trim the package cache.\n" CLR_RESET);
  }
  if (has_flatpak) {
    run_cmd(fp_sys_cln);
    run_cmd(fp_usr_cln);
  }

  if (has_pacdiff) {
    print_step(&step, total_steps,
               "Scanning for unmerged .pacnew / .pacsave files...");
    run_cmd(pacdiff);
  }

  print_step(&step, total_steps, "Checking for degraded systemd services...");
  if (run_cmd(sysok) == 0) {
    printf(CLR_GREEN "[✓] All systemd services healthy.\n" CLR_RESET);
  } else {
    run_cmd(sysfail);
  }

  if (have_cmd("fastfetch")) {
    printf("\n");
    run_cmd(fetch);
  }

  check_kernel_reboot();

  // Re-run the stale library scan as root so system daemons (sshd, systemd-*,
  // dbus, ...) are covered. sudo reuses the credentials kept alive since
  // acquire_sudo(); fall back to the unprivileged user-only scan otherwise.
  char self_exe[PATH_MAX];
  ssize_t self_len = readlink("/proc/self/exe", self_exe, sizeof(self_exe) - 1);
  int scanned_as_root = 0;
  if (self_len > 0) {
    self_exe[self_len] = '\0';
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
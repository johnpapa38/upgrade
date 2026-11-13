#include "upgrade.h"

// Detects true orphaned dependencies via libalpm (`pacman -Qdtq` equivalent:
// installed as a dependency and neither required nor optionally required by any
// package). Skips spawning an external helper altogether when 0 orphans exist.
void sweep_orphans(const char *aur_helper) {
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

  if (aur_helper && strcmp(aur_helper, "yay") == 0) {
    char *const cmd[] = {"yay", "-Yc", "--noconfirm", NULL};
    run_cmd(cmd);
  } else if (aur_helper && strcmp(aur_helper, "paru") == 0) {
    char *const cmd[] = {"paru", "-c", "--noconfirm", NULL};
    run_cmd(cmd);
  } else {
    char **args = malloc((count + 5) * sizeof(char *));
    if (args) {
      size_t n = 0;
      args[n++] = "sudo";
      args[n++] = "pacman";
      args[n++] = "-Rns";
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
void clean_pacman_cache(void) {
  const int keep_versions = 2;
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

    size_t keep = (alpm_db_get_pkg(localdb, items[i].pkgname) != NULL)
                      ? (size_t)keep_versions
                      : 0;
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
           "[✓] Pacman cache already clean (kept last %d version(s)).\n"
           CLR_RESET,
           keep_versions);
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
void clean_aur_cache(void) {
  const int keep_versions = 2;
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

    size_t keep = (alpm_db_get_pkg(localdb, items[i].pkgname) != NULL)
                      ? (size_t)keep_versions
                      : 0;
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
           "[✓] AUR build cache already clean (kept last %d version(s)).\n"
           CLR_RESET,
           keep_versions);
  }
}

static unsigned long long sum_dir_bytes(const char *dir, int depth) {
  if (depth > 4)
    return 0;
  DIR *d = opendir(dir);
  if (!d)
    return 0;

  unsigned long long total = 0;
  struct dirent *ent;
  while ((ent = readdir(d)) != NULL) {
    if (ent->d_name[0] == '.')
      continue;
    char path[PATH_MAX];
    if (snprintf(path, sizeof(path), "%s/%s", dir, ent->d_name) >=
        (int)sizeof(path))
      continue;
    struct stat st;
    if (lstat(path, &st) != 0)
      continue;
    if (S_ISDIR(st.st_mode))
      total += sum_dir_bytes(path, depth + 1);
    else if (S_ISREG(st.st_mode))
      total += (unsigned long long)st.st_blocks * 512ULL;
  }
  closedir(d);
  return total;
}

// Audits /var/log/journal disk usage and trims archived systemd journals to
// 500 MiB during maintenance when they grow beyond that cap.
void clean_systemd_journal(int check_only) {
  const int cap_mib = 500;
  const unsigned long long cap_bytes =
      (unsigned long long)cap_mib * 1024ULL * 1024ULL;
  unsigned long long before = sum_dir_bytes("/var/log/journal", 0);
  if (before == 0)
    return;

  double before_mib = (double)before / (1024.0 * 1024.0);
  if (before <= cap_bytes) {
    if (!check_only) {
      printf(CLR_GREEN "[✓] Systemd journal: %.1f MiB used (within %d MiB "
                       "cap).\n" CLR_RESET,
             before_mib, cap_mib);
    }
    return;
  }

  if (check_only) {
    printf(CLR_YELLOW "[!] Systemd journal is using %.1f MiB "
                      "(/var/log/journal; trimmed on upgrade).\n" CLR_RESET,
           before_mib);
    return;
  }

  if (!have_cmd("journalctl"))
    return;

  char vac_arg[32];
  snprintf(vac_arg, sizeof(vac_arg), "--vacuum-size=%dM", cap_mib);
  char out[4096];
  int rc = -1;
  if (geteuid() == 0) {
    char *const cmd[] = {"journalctl", vac_arg, NULL};
    capture_cmd_output(cmd, out, sizeof(out), &rc);
  } else {
    char *const cmd[] = {"sudo", "-n", "journalctl", vac_arg, NULL};
    capture_cmd_output(cmd, out, sizeof(out), &rc);
  }

  unsigned long long after = sum_dir_bytes("/var/log/journal", 0);
  if (after < before) {
    double freed_mib = (double)(before - after) / (1024.0 * 1024.0);
    printf(CLR_GREEN "[✓] Systemd journal: vacuumed %.1f MiB (now %.1f "
                     "MiB).\n" CLR_RESET,
           freed_mib, (double)after / (1024.0 * 1024.0));
  }
}

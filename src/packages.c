#include "upgrade.h"

// Runs pacman's native local-database consistency audit (`pacman -Dkq`), which
// checks dependency satisfaction, package conflicts, required database files,
// and duplicate file ownership. Read-only and does not need root.
void check_package_database(void) {
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
void check_dkms_status(void) {
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

// Packages with known CVEs for which a fixed version is already in the repos.
void check_arch_audit(void) {
  if (!have_cmd("arch-audit")) {
    printf(CLR_MAGENTA "[i] CVE audit skipped: arch-audit not installed "
                       "(pacman -S arch-audit).\n" CLR_RESET);
    return;
  }
  char buf[16384];
  int rc = -1;
  char *const cmd[] = {"arch-audit", "--upgradable", NULL};
  ssize_t n = capture_cmd_output(cmd, buf, sizeof(buf), &rc);
  if (n < 0 || (n == 0 && rc > 1)) {
    printf(CLR_YELLOW "[!] CVE audit failed (security tracker unreachable?).\n"
                      CLR_RESET);
    return;
  }
  if (n == 0 || buf[strspn(buf, " \t\r\n")] == '\0') {
    printf(CLR_GREEN "[✓] CVE audit: no vulnerable packages with a fix "
                     "available.\n" CLR_RESET);
    return;
  }
  printf(CLR_YELLOW "[!] Vulnerable packages with a fixed version "
                    "available:\n" CLR_RESET);
  print_capped_lines(buf, 12);
}

// AUR/foreign packages linked against libraries that were just bumped.
void check_rebuilds(void) {
  if (!have_cmd("checkrebuild")) {
    printf(CLR_MAGENTA "[i] Rebuild check skipped: checkrebuild not installed "
                       "(rebuild-detector).\n" CLR_RESET);
    return;
  }
  char buf[8192];
  int rc = -1;
  char *const cmd[] = {"checkrebuild", NULL};
  ssize_t n = capture_cmd_output(cmd, buf, sizeof(buf), &rc);
  if (n < 0 || buf[strspn(buf, " \t\r\n")] == '\0') {
    printf(CLR_GREEN "[✓] No packages need a rebuild after library "
                     "updates.\n" CLR_RESET);
    return;
  }
  printf(CLR_YELLOW "[!] Packages needing a rebuild (linked against replaced "
                    "libraries):\n" CLR_RESET);
  print_capped_lines(buf, 20);
}

// Checks cached LVFS metadata (if fwupd is installed) for pending device
// firmware updates without blocking on network downloads.
void check_firmware_updates(void) {
  if (!have_cmd("fwupdmgr"))
    return;

  char buf[16384];
  int rc = -1;
  char *const cmd[] = {"fwupdmgr", "get-updates", "--json", NULL};
  if (capture_cmd_output(cmd, buf, sizeof(buf), &rc) <= 0 || buf[0] != '{')
    return;

  const char *devs = strstr(buf, "\"Devices\"");
  if (!devs)
    return;

  size_t count = 0;
  const char *p = devs;
  while ((p = strstr(p, "\"Releases\"")) != NULL) {
    count++;
    p += 10;
  }

  if (count > 0) {
    printf(CLR_YELLOW "[!] Firmware: %zu device(s) have LVFS updates available "
                      "(run `fwupdmgr update`).\n" CLR_RESET,
           count);
  } else {
    printf(CLR_GREEN "[✓] Firmware: no pending LVFS device updates.\n"
                     CLR_RESET);
  }
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
void scan_pacnew_files(void) {
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

// Audits four common configuration drift traps on Arch Linux:
//   1. Unmanaged binaries in /usr/local/bin or ~/.local/bin shadowing /usr/bin
//      packages (so pacman upgrades /usr/bin/<pkg> while PATH runs the old copy)
//   2. Broken symlinks in /usr/local/bin or ~/.local/bin pointing to deleted
//      targets
//   3. Full unit copies in /etc/systemd/system/*.service masking package units
//      in /usr/lib/systemd/system/ while pointing at /usr/local or missing bins
//   4. Dangling .wants/.requires symlinks left behind by removed services
void check_shadowed_paths(void) {
  struct str_vec shadowed_bins = {NULL, 0, 0};
  struct str_vec broken_bin_links = {NULL, 0, 0};
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

      struct stat lst, st;
      if (lstat(cand, &lst) == 0 && S_ISLNK(lst.st_mode) &&
          stat(cand, &st) != 0 && errno == ENOENT) {
        char target[PATH_MAX];
        ssize_t tlen = readlink(cand, target, sizeof(target) - 1);
        char msg[PATH_MAX * 2 + 16];
        if (tlen > 0) {
          target[tlen] = '\0';
          snprintf(msg, sizeof(msg), "%s -> %s", cand, target);
        } else {
          snprintf(msg, sizeof(msg), "%s", cand);
        }
        str_vec_add_unique(&broken_bin_links, msg);
        continue;
      }

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

  if (broken_bin_links.count > 0) {
    qsort(broken_bin_links.items, broken_bin_links.count, sizeof(char *),
          cmp_cstr_ptr);
    printf(CLR_YELLOW "[!] Broken symlinks in PATH bin directories (%zu):\n"
                      CLR_RESET,
           broken_bin_links.count);
    for (size_t i = 0; i < broken_bin_links.count; i++) {
      printf("    - %s\n", broken_bin_links.items[i]);
      free(broken_bin_links.items[i]);
    }
  }
  free(broken_bin_links.items);

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

static int root_is_btrfs(void) {
  FILE *fp = fopen("/proc/self/mountinfo", "r");
  if (!fp)
    return 0;
  int btrfs = 0;
  char line[1024];
  while (fgets(line, sizeof(line), fp)) {
    char mnt[512], fstype[64];
    if (sscanf(line, "%*s %*s %*s %*s %511s", mnt) != 1 ||
        strcmp(mnt, "/") != 0)
      continue;
    const char *sep = strstr(line, " - ");
    if (sep && sscanf(sep + 3, "%63s", fstype) == 1)
      btrfs = (strcmp(fstype, "btrfs") == 0);
  }
  fclose(fp);
  return btrfs;
}

// Creates (or, with check_only, just reports) a rollback point before the
// upgrade. Never aborts the upgrade: a failed snapshot only warns.
void pre_upgrade_snapshot(int check_only) {
  if (access("/usr/share/libalpm/hooks/05-snap-pac-pre.hook", F_OK) == 0) {
    printf(CLR_GREEN "[✓] Snapshots: snap-pac will take pre/post snapshots "
                     "around the transaction.\n" CLR_RESET);
    return;
  }

  if (have_cmd("snapper") && access("/etc/snapper/configs/root", F_OK) == 0) {
    if (check_only) {
      printf(CLR_GREEN "[✓] Snapshots: snapper 'root' config present — a "
                       "pre-upgrade snapshot will be taken.\n" CLR_RESET);
      return;
    }
    printf(CLR_CYAN ":: Creating pre-upgrade snapper snapshot...\n" CLR_RESET);
    char *const cmd[] = {"sudo",    "snapper",   "--config",
                         "root",    "create",    "--type",
                         "single",  "--cleanup-algorithm", "number",
                         "--description", "upgrade: pre-upgrade", NULL};
    if (run_cmd(cmd) != 0)
      printf(CLR_YELLOW "[!] Snapshot failed — continuing without a rollback "
                        "point.\n" CLR_RESET);
    return;
  }

  if (have_cmd("timeshift") && !check_only) {
    printf(CLR_CYAN ":: Creating pre-upgrade Timeshift snapshot...\n" CLR_RESET);
    char *const cmd[] = {"sudo",     "timeshift", "--create",
                         "--comments", "upgrade: pre-upgrade", "--scripted",
                         NULL};
    if (run_cmd(cmd) != 0)
      printf(CLR_YELLOW "[!] Timeshift snapshot failed (not configured?) — "
                        "continuing.\n" CLR_RESET);
    return;
  }

  if (root_is_btrfs())
    printf(CLR_MAGENTA "[i] / is btrfs but no snapshot tool is set up — "
                       "snapper + snap-pac gives you one-command rollback "
                       "after a bad upgrade.\n" CLR_RESET);
}

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
  if (!have_cmd("arch-audit"))
    return;
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

// Extracts unique package names from `checkrebuild` lines whose first column
// is `foreign` (e.g. "foreign\textremetuxracer" or "foreign  viber").
size_t parse_checkrebuild_foreign(const char *buf, struct str_vec *out) {
  if (!buf || !out)
    return 0;
  for (const char *p = buf; *p != '\0';) {
    const char *nl = strchr(p, '\n');
    size_t len = nl ? (size_t)(nl - p) : strlen(p);
    const char *end = p + len;
    while (p < end && (*p == ' ' || *p == '\t' || *p == '\r'))
      p++;
    if ((size_t)(end - p) > 7 && strncmp(p, "foreign", 7) == 0 &&
        (p[7] == ' ' || p[7] == '\t')) {
      const char *q = p + 7;
      while (q < end && (*q == ' ' || *q == '\t'))
        q++;
      char pkg[128];
      size_t pi = 0;
      while (q < end && *q != ' ' && *q != '\t' && *q != '\r' &&
             pi + 1 < sizeof(pkg)) {
        pkg[pi++] = *q++;
      }
      pkg[pi] = '\0';
      if (pkg[0] != '\0')
        str_vec_add_unique(out, pkg);
    }
    if (!nl)
      break;
    p = nl + 1;
  }
  return out->count;
}

// AUR/foreign packages linked against libraries that were just bumped.
void check_rebuilds(const char *aur_helper, int check_only) {
  if (!have_cmd("checkrebuild"))
    return;
  char buf[8192];
  int rc = -1;
  char *const cmd[] = {"checkrebuild", NULL};
  ssize_t n = capture_cmd_output(cmd, buf, sizeof(buf), &rc);
  if (n < 0 || buf[strspn(buf, " \t\r\n")] == '\0') {
    printf(CLR_GREEN "[✓] No packages need a rebuild after library "
                     "updates.\n" CLR_RESET);
    return;
  }

  struct str_vec foreign_pkgs = {NULL, 0, 0};
  parse_checkrebuild_foreign(buf, &foreign_pkgs);

  if (check_only || !aur_helper || foreign_pkgs.count == 0) {
    printf(CLR_YELLOW "[!] Packages needing a rebuild (linked against replaced "
                      "libraries):\n" CLR_RESET);
    print_capped_lines(buf, 20);
    str_vec_free(&foreign_pkgs);
    return;
  }

  printf(CLR_YELLOW "[!] %zu AUR package(s) need a rebuild — rebuilding "
                    "automatically...\n" CLR_RESET,
         foreign_pkgs.count);
  size_t failed = 0, removed = 0;
  for (size_t i = 0; i < foreign_pkgs.count; i++) {
    char *pkg = foreign_pkgs.items[i];
    printf(CLR_CYAN ":: Rebuilding '%s'...\n" CLR_RESET, pkg);
    char *const rcmd[] = {(char *)aur_helper, "-S", "--noconfirm",
                          "--rebuild", pkg, NULL};
    int rrc = run_cmd(rcmd);
    if (rrc == 0)
      continue;
    if (rrc == -2) {
      str_vec_free(&foreign_pkgs);
      return;
    }

    failed++;
    printf(CLR_YELLOW "[!] '%s' failed to rebuild — removing so it does not "
                      "block your system...\n" CLR_RESET,
           pkg);
    char *const rm_cmd[] = {(char *)aur_helper, "-Rns", "--noconfirm", pkg,
                            NULL};
    if (run_cmd(rm_cmd) == 0) {
      removed++;
      printf(CLR_GREEN "[✓] Removed broken AUR package '%s'.\n" CLR_RESET,
             pkg);
    } else {
      printf(CLR_YELLOW "[!] Could not remove '%s' automatically (other "
                        "packages may depend on it).\n" CLR_RESET,
             pkg);
    }
  }
  if (failed == 0) {
    printf(CLR_GREEN "[✓] Rebuilt all flagged AUR package(s).\n" CLR_RESET);
  } else if (removed == failed) {
    printf(CLR_GREEN "[✓] Rebuilt or removed all broken AUR package(s).\n"
                     CLR_RESET);
  }
  str_vec_free(&foreign_pkgs);
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

// Previews pending Flatpak system and user updates in check mode.
void check_flatpak_updates(void) {
  if (!have_cmd("flatpak"))
    return;

  char list_buf[16384];
  int list_rc = -1;
  char *const list_cmd[] = {"flatpak", "list", "--columns=application", NULL};
  if (capture_cmd_output(list_cmd, list_buf, sizeof(list_buf), &list_rc) <= 0 ||
      list_buf[strspn(list_buf, " \t\r\n")] == '\0') {
    return; // No Flatpak apps or runtimes installed
  }

  char sys_buf[16384], usr_buf[16384];
  int rc = -1;
  char *const sys_cmd[] = {"flatpak", "remote-ls", "--updates", "--system",
                           "--columns=application,version,branch", NULL};
  char *const usr_cmd[] = {"flatpak", "remote-ls", "--updates", "--user",
                           "--columns=application,version,branch", NULL};
  ssize_t sn = capture_cmd_output(sys_cmd, sys_buf, sizeof(sys_buf), &rc);
  ssize_t un = capture_cmd_output(usr_cmd, usr_buf, sizeof(usr_buf), &rc);

  int has_sys = (sn > 0 && sys_buf[strspn(sys_buf, " \t\r\n")] != '\0');
  int has_usr = (un > 0 && usr_buf[strspn(usr_buf, " \t\r\n")] != '\0');
  if (!has_sys && !has_usr) {
    printf(CLR_GREEN "[✓] Flatpak: all apps & runtimes up to date.\n"
                     CLR_RESET);
    return;
  }

  printf(CLR_YELLOW "[!] Pending Flatpak Updates:\n" CLR_RESET);
  if (has_sys)
    print_capped_lines(sys_buf, 15);
  if (has_usr)
    print_capped_lines(usr_buf, 15);
}

// Previews pending Snap package updates in check mode.
void check_snap_updates(void) {
  if (!have_cmd("snap"))
    return;

  char buf[16384];
  int rc = -1;
  char *const cmd[] = {"snap", "refresh", "--list", NULL};
  ssize_t n = capture_cmd_output(cmd, buf, sizeof(buf), &rc);
  if (n < 0 || rc != 0)
    return;

  size_t non_empty_lines = 0;
  for (const char *p = buf; *p != '\0';) {
    const char *nl = strchr(p, '\n');
    size_t len = nl ? (size_t)(nl - p) : strlen(p);
    if (len > 0 && strspn(p, " \t\r") < len)
      non_empty_lines++;
    if (!nl)
      break;
    p = nl + 1;
  }

  if (non_empty_lines < 2) {
    printf(CLR_GREEN "[✓] Snap: all packages up to date.\n" CLR_RESET);
    return;
  }

  printf(CLR_YELLOW "[!] Pending Snap Updates:\n" CLR_RESET);
  print_capped_lines(buf, 15);
}

static int dir_has_uki_for_kernel(const char *esp_dir, const char *pkgbase,
                                  const char *kver, int *saw_eacces) {
  char uki_dir[PATH_MAX];
  if (snprintf(uki_dir, sizeof(uki_dir), "%s/EFI/Linux", esp_dir) >=
      (int)sizeof(uki_dir))
    return 0;
  DIR *d = opendir(uki_dir);
  if (!d) {
    if (errno == EACCES && saw_eacces)
      *saw_eacces = 1;
    return 0;
  }

  int found = 0;
  struct dirent *ent;
  while ((ent = readdir(d)) != NULL) {
    size_t len = strlen(ent->d_name);
    if (len < 4 || strcmp(ent->d_name + len - 4, ".efi") != 0)
      continue;
    char p[PATH_MAX];
    struct stat st;
    if (snprintf(p, sizeof(p), "%s/%s", uki_dir, ent->d_name) < (int)sizeof(p) &&
        stat(p, &st) == 0 && S_ISREG(st.st_mode) && st.st_size > 0) {
      if ((pkgbase[0] && strstr(ent->d_name, pkgbase)) ||
          strstr(ent->d_name, kver) || strstr(ent->d_name, "linux")) {
        found = 1;
        break;
      }
    }
  }
  closedir(d);
  return found;
}

// Verifies that installed kernels under /usr/lib/modules/* have intact
// modules.dep.bin and (when /boot or ESP is readable) non-empty initramfs or
// UKI boot images so a failed mkinitcpio/dracut hook is caught before reboot.
void check_boot_integrity(void) {
  DIR *md = opendir("/usr/lib/modules");
  if (!md)
    return;

  static const char *const esps[3] = {"/boot", "/efi", "/boot/efi"};
  int checked = 0, problems = 0;
  struct dirent *ent;

  while ((ent = readdir(md)) != NULL) {
    if (ent->d_name[0] == '.')
      continue;
    char kdir[PATH_MAX];
    if (snprintf(kdir, sizeof(kdir), "/usr/lib/modules/%s", ent->d_name) >=
        (int)sizeof(kdir))
      continue;
    struct stat kst;
    if (stat(kdir, &kst) != 0 || !S_ISDIR(kst.st_mode))
      continue;

    char pkgbase_path[PATH_MAX], pkgbase[64] = "";
    snprintf(pkgbase_path, sizeof(pkgbase_path), "/usr/lib/modules/%.255s/pkgbase",
             ent->d_name);
    if (read_small_file(pkgbase_path, pkgbase, sizeof(pkgbase)) != 0)
      continue; // Not a pacman-managed kernel tree (e.g. empty leftover dir)

    checked++;
    char dep_path[PATH_MAX];
    struct stat dst;
    snprintf(dep_path, sizeof(dep_path), "/usr/lib/modules/%.255s/modules.dep.bin",
             ent->d_name);
    if (stat(dep_path, &dst) != 0 || dst.st_size <= 0) {
      printf(CLR_RED "[!] Boot integrity (%s, %s): missing/empty "
                     "modules.dep.bin — run `sudo depmod %s`!\n" CLR_RESET,
             ent->d_name, pkgbase, ent->d_name);
      problems++;
      continue;
    }

    int saw_eacces = 0;
    int has_vmlinuz = 0, has_initramfs = 0, has_uki = 0;
    for (int i = 0; i < 3; i++) {
      struct stat est;
      if (stat(esps[i], &est) != 0)
        continue;
      if (access(esps[i], R_OK | X_OK) != 0 && errno == EACCES) {
        saw_eacces = 1;
        continue;
      }

      char vm_path[PATH_MAX], img_path[PATH_MAX];
      struct stat vst, ist;
      if (snprintf(vm_path, sizeof(vm_path), "%s/vmlinuz-%s", esps[i],
                   pkgbase) < (int)sizeof(vm_path) &&
          stat(vm_path, &vst) == 0 && S_ISREG(vst.st_mode) &&
          vst.st_size > 0) {
        has_vmlinuz = 1;
      }
      if (snprintf(img_path, sizeof(img_path), "%s/initramfs-%s.img", esps[i],
                   pkgbase) < (int)sizeof(img_path) &&
          stat(img_path, &ist) == 0 && S_ISREG(ist.st_mode) &&
          ist.st_size > 0) {
        has_initramfs = 1;
      }
      if (dir_has_uki_for_kernel(esps[i], pkgbase, ent->d_name, &saw_eacces))
        has_uki = 1;
    }

    if (has_vmlinuz && !has_initramfs && !has_uki) {
      printf(CLR_RED "[!] Boot integrity (%s, %s): kernel present without "
                     "initramfs-%s.img — run `sudo mkinitcpio -P` before "
                     "rebooting!\n" CLR_RESET,
             ent->d_name, pkgbase, pkgbase);
      problems++;
    } else if (has_initramfs || has_uki) {
      printf(CLR_GREEN "[✓] Boot integrity (%s, %s): modules.dep.bin & %s "
                       "verified.\n" CLR_RESET,
             ent->d_name, pkgbase, has_uki ? "UKI" : "initramfs");
    } else if (saw_eacces) {
      printf(CLR_GREEN "[✓] Kernel modules intact (%s, %s).\n" CLR_RESET,
             ent->d_name, pkgbase);
    }
  }
  closedir(md);

  if (checked == 0) {
    printf(CLR_MAGENTA "[i] Boot integrity: no pacman kernel pkgbase trees "
                       "found under /usr/lib/modules.\n" CLR_RESET);
  } else if (problems > 0) {
    printf(CLR_RED "    Verify your bootloader/initramfs before rebooting.\n"
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

static void collect_pacnew_files(struct str_vec *found) {
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
              str_vec_add_unique(found, path);
          }
        }
      }
    }
    alpm_release(handle);
  }

  walk_etc_pacfiles("/etc", 0, found);
  if (found->count > 1)
    qsort(found->items, found->count, sizeof(char *), cmp_cstr_ptr);
}

// Native replacement for `pacdiff -o`: checks every installed package's backup
// array via libalpm AND walks /etc for .pacsave files from removed packages.
size_t scan_pacnew_files(void) {
  struct str_vec found = {NULL, 0, 0};
  collect_pacnew_files(&found);

  if (found.count == 0) {
    printf(CLR_GREEN "[✓] No unmerged .pacnew / .pacsave files.\n" CLR_RESET);
  } else {
    printf(CLR_YELLOW "[!] Unmerged config files requiring review (%zu):\n"
                      CLR_RESET,
           found.count);
    for (size_t i = 0; i < found.count; i++)
      printf("    - %s\n", found.items[i]);
  }
  size_t count = found.count;
  str_vec_free(&found);
  return count;
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
}

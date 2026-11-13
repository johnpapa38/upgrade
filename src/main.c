#include "upgrade.h"

static void usage(const char *prog) {
  printf("Usage: %s [options]\n"
         "  (no args)   Update packages, clean caches, and check system health\n"
         "  -c, --check Preview available updates and health (read-only)\n"
         "  -v          Show version\n"
         "  -h          Show this help\n",
         prog);
}

static void run_cleanup_stage(const char *aur_helper, const char *self_exe,
                              ssize_t self_len, int has_flatpak, int *step,
                              int total_steps) {
  print_step(step, total_steps, "Sweeping orphaned dependencies...");
  sweep_orphans(aur_helper);

  print_step(step, total_steps,
             has_flatpak
                 ? "Cleaning caches (pacman/AUR, journal & Flatpak)..."
                 : "Cleaning caches (pacman/AUR & systemd journal)...");

  if (self_len > 0) {
    char *const sudo_cache[] = {"sudo", (char *)self_exe, "--clean-cache",
                                NULL};
    if (run_cmd(sudo_cache) != 0) {
      clean_pacman_cache();
      clean_systemd_journal(0);
    }
  } else {
    clean_pacman_cache();
    clean_systemd_journal(0);
  }
  clean_aur_cache();
  if (has_flatpak) {
    char *const fp_sys_cln[] = {"sudo", "flatpak",  "uninstall",
                                "--system", "--unused", "-y", NULL};
    char *const fp_usr_cln[] = {"flatpak", "uninstall", "--user", "--unused",
                                "-y", NULL};
    run_cmd(fp_sys_cln);
    run_cmd(fp_usr_cln);
  }
}

int main(int argc, char *argv[]) {
  int check_only = 0;
  int stale_libs_only = 0;
  int clean_cache_only = 0;
  int scan_pacnew_only = 0;
  int boot_check_only = 0;

  for (int i = 1; i < argc; i++) {
    if (strcmp(argv[i], "-c") == 0 || strcmp(argv[i], "--check") == 0) {
      check_only = 1;
    } else if (strcmp(argv[i], "--stale-libs") == 0) {
      stale_libs_only = 1;
    } else if (strcmp(argv[i], "--clean-cache") == 0) {
      clean_cache_only = 1;
    } else if (strcmp(argv[i], "--scan-pacnew") == 0) {
      scan_pacnew_only = 1;
    } else if (strcmp(argv[i], "--boot-check") == 0) {
      boot_check_only = 1;
    } else if (strcmp(argv[i], "-v") == 0 ||
               strcmp(argv[i], "--version") == 0) {
      printf("upgrade %s\n", UPGRADE_VERSION);
      return EXIT_SUCCESS;
    } else if (strcmp(argv[i], "-h") == 0 || strcmp(argv[i], "--help") == 0) {
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
    clean_systemd_journal(0);
    return EXIT_SUCCESS;
  }
  if (scan_pacnew_only) {
    (void)scan_pacnew_files();
    return EXIT_SUCCESS;
  }
  if (boot_check_only) {
    check_boot_integrity();
    return EXIT_SUCCESS;
  }

  // Refuse to run full upgrade as root because yay/paru/makepkg must run as a
  // normal user and elevate via sudo only when needed.
  if (!check_only && geteuid() == 0) {
    fprintf(stderr,
            CLR_RED ":: Error: Run as normal user, not root.\n" CLR_RESET);
    return EXIT_FAILURE;
  }

  const char *aur_helper =
      have_cmd("yay") ? "yay" : (have_cmd("paru") ? "paru" : NULL);
  int has_flatpak = have_cmd("flatpak");
  int has_snap = have_cmd("snap");

  char self_exe[PATH_MAX];
  ssize_t self_len = readlink("/proc/self/exe", self_exe, sizeof(self_exe) - 1);
  if (self_len > 0)
    self_exe[self_len] = '\0';

  int stale_lock = 0;
  if (!check_only) {
    int lock_rc = check_pacman_lock(0);
    if (lock_rc == -1)
      return EXIT_FAILURE;
    if (lock_rc == -2)
      stale_lock = 1;
  }

  int keyring_needs_update = 0;
  run_alpm_telemetry(check_only, aur_helper != NULL, &keyring_needs_update);

  if (check_only) {
    printf("\n");
    check_pacman_lock(1);
    check_pacman_keyring();
    check_mirrorlist_health(1);
    if (has_flatpak)
      check_flatpak_updates();
    if (has_snap)
      check_snap_updates();
    pre_upgrade_snapshot(1);
    check_package_database();
    check_dkms_status();
    check_arch_audit();
    check_rebuilds(aur_helper, 1);
    check_firmware_updates();
    check_boot_integrity();
    (void)scan_pacnew_files();
    check_shadowed_paths();
    clean_systemd_journal(1);
    check_boot_mounts(1);
    check_systemd_health();
    check_boot_coredumps();
    check_boot_performance();
    check_hardware_health(1);
    check_kernel_reboot();
    check_stale_libs();
    return EXIT_SUCCESS;
  }

  // Pre-flight storage & boot/ESP mount check before touching packages
  printf("\n");
  check_pacman_keyring();
  check_mirrorlist_health(0);
  if (check_disk_space("/", MIN_FREE_GIB) != 0 ||
      check_disk_space("/var/cache/pacman/pkg", MIN_FREE_GIB) != 0 ||
      check_boot_mounts(0) != 0) {
    return EXIT_FAILURE;
  }

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

  if (stale_lock) {
    char *const rm_lck[] = {"sudo", "rm", "-f", "/var/lib/pacman/db.lck", NULL};
    if (run_cmd(rm_lck) != 0) {
      fprintf(stderr,
              CLR_RED ":: Error: Could not clear /var/lib/pacman/db.lck.\n"
                      CLR_RESET);
      return EXIT_FAILURE;
    }
  }

  pre_upgrade_snapshot(0);

  off_t log_start_off = get_pacman_log_offset();
  struct timespec t_start, t_end;
  clock_gettime(CLOCK_MONOTONIC, &t_start);

  char *const up_kr[] = {"sudo", "pacman", "-Sy", "--needed",
                         "--noconfirm", "archlinux-keyring", NULL};

  // If a keyring update was detected, upgrade archlinux-keyring first so new
  // packager signatures don't fail the main transaction.
  if (keyring_needs_update) {
    printf(CLR_CYAN "\n:: Refreshing archlinux-keyring before main "
                    "transaction...\n" CLR_RESET);
    run_cmd(up_kr);
  }

  // `--ask=4` (ALPM_QUESTION_CONFLICT_PKG) lets pacman/yay/paru swap replaced
  // packages atomically without ever prompting.
  char *const up_aur[] = {(char *)aur_helper, "-Syu", "--noconfirm", "--ask=4",
                          NULL};
  char *const up_pacman[] = {"sudo", "pacman", "-Syu", "--noconfirm",
                             "--ask=4", NULL};
  char *const fp_sys_up[] = {"sudo", "flatpak", "update", "--system", "-y",
                             NULL};
  char *const fp_usr_up[] = {"flatpak", "update", "--user", "-y", NULL};
  char *const snap_up[] = {"sudo", "snap", "refresh", NULL};

  int tx_rc = -1;
  if (aur_helper) {
    print_step(&step, total_steps,
               "Synchronizing & upgrading packages (Repo + AUR)...");
    tx_rc = run_cmd(up_aur);
    if (tx_rc == -1 && !keyring_needs_update &&
        access("/var/lib/pacman/db.lck", F_OK) != 0) {
      printf(CLR_YELLOW "\n:: Refreshing keyring and retrying...\n" CLR_RESET);
      run_cmd(up_kr);
      tx_rc = run_cmd(up_aur);
    }
    if (tx_rc == -1 && access("/var/lib/pacman/db.lck", F_OK) != 0) {
      printf(CLR_YELLOW "\n:: AUR upgrade failed — updating official system "
                        "packages...\n" CLR_RESET);
      tx_rc = run_cmd(up_pacman);
    }
  } else {
    print_step(&step, total_steps, "Synchronizing & upgrading system packages...");
    tx_rc = run_cmd(up_pacman);
    if (tx_rc == -1 && !keyring_needs_update &&
        access("/var/lib/pacman/db.lck", F_OK) != 0) {
      printf(CLR_YELLOW "\n:: Refreshing keyring and retrying...\n" CLR_RESET);
      run_cmd(up_kr);
      tx_rc = run_cmd(up_pacman);
    }
  }
  if (tx_rc != 0) {
    fprintf(stderr, CLR_RED ":: Upgrade failed.\n" CLR_RESET);
    return EXIT_FAILURE;
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

  print_step(&step, total_steps, "Verifying package database & rebuilds...");
  check_package_database();
  check_dkms_status();
  check_rebuilds(aur_helper, 0);
  check_arch_audit();
  check_firmware_updates();

  run_cleanup_stage(aur_helper, self_exe, self_len, has_flatpak, &step,
                    total_steps);

  print_step(&step, total_steps,
             "Scanning for unmerged .pacnew / .pacsave & shadowed paths...");
  if (self_len > 0) {
    char *const sudo_pacnew[] = {"sudo", self_exe, "--scan-pacnew", NULL};
    if (run_cmd(sudo_pacnew) != 0)
      (void)scan_pacnew_files();
  } else {
    (void)scan_pacnew_files();
  }
  check_shadowed_paths();

  print_step(&step, total_steps,
             "Checking system, hardware, boot & running apps...");
  check_systemd_health();
  check_boot_coredumps();
  check_boot_performance();
  check_hardware_health(0);

  print_sys_summary();

  if (self_len > 0) {
    char *const sudo_boot[] = {"sudo", self_exe, "--boot-check", NULL};
    if (run_cmd(sudo_boot) != 0)
      check_boot_integrity();
  } else {
    check_boot_integrity();
  }
  check_kernel_reboot();

  int scanned_as_root = 0;
  if (self_len > 0) {
    char *const sudo_scan[] = {"sudo", self_exe, "--stale-libs", NULL};
    scanned_as_root = (run_cmd(sudo_scan) == 0);
  }
  if (!scanned_as_root)
    check_stale_libs();

  struct tx_summary tx = {0};
  summarize_pacman_log_delta(log_start_off, &tx);

  clock_gettime(CLOCK_MONOTONIC, &t_end);
  double elapsed =
      (t_end.tv_sec - t_start.tv_sec) + (t_end.tv_nsec - t_start.tv_nsec) / 1e9;
  printf(CLR_YELLOW "\n:: Done in %.2f seconds.\n" CLR_RESET, elapsed);

  return EXIT_SUCCESS;
}

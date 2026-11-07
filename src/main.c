#include "upgrade.h"

static void usage(const char *prog) {
  printf("Usage: %s [options]\n"
         "Zero-extra-dependency Arch Linux maintenance: official repos + AUR +\n"
         "Flatpak + Snap upgrades, native cache/orphan cleanup, and health "
         "checks.\n\n"
         "  -c, --check     Read-only update, package DB, service, boot & "
         "hardware report\n"
         "  -y, --yes       Unattended: auto-confirm every package manager "
         "prompt\n"
         "      --hw        Quick hardware health (SMART, RAM, thermals, "
         "kernel log) & summary\n"
         "  -v, --version   Show version\n"
         "  -h, --help      Show this help\n\n"
         "Run as your normal user; sudo is requested once and kept alive.\n",
         prog);
}

int main(int argc, char *argv[]) {
  int check_only = 0;
  int auto_yes = 0;
  int hw_only = 0;
  int stale_libs_only = 0;
  int clean_cache_only = 0;
  int scan_pacnew_only = 0;

  // Parse CLI flags:
  //   -c, --check   : Run read-only update + package/system/hardware checks
  //   -y, --yes     : Auto-confirm yay/paru/pacman/flatpak prompts (unattended)
  //   --hw          : Run standalone hardware health & system summary
  //   -v, --version : Show version
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
    else if (strcmp(argv[i], "--hw") == 0)
      hw_only = 1;
    else if (strcmp(argv[i], "--stale-libs") == 0)
      stale_libs_only = 1;
    else if (strcmp(argv[i], "--clean-cache") == 0)
      clean_cache_only = 1;
    else if (strcmp(argv[i], "--scan-pacnew") == 0)
      scan_pacnew_only = 1;
    else if (strcmp(argv[i], "-v") == 0 || strcmp(argv[i], "--version") == 0) {
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
    scan_pacnew_files();
    return EXIT_SUCCESS;
  }
  if (hw_only) {
    check_hardware_health(1);
    print_sys_summary();
    check_kernel_reboot();
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

  int keyring_needs_update = 0;
  run_alpm_telemetry(check_only, aur_helper != NULL, &keyring_needs_update);

  if (check_only) {
    printf("\n");
    check_pacman_lock(1);
    check_pacman_keyring();
    pre_upgrade_snapshot(1);
    check_package_database();
    check_dkms_status();
    check_arch_audit();
    check_rebuilds();
    check_firmware_updates();
    scan_pacnew_files();
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

  // Ensure no other pacman/yay instance holds the database lock
  if (check_pacman_lock(0) != 0)
    return EXIT_FAILURE;

  // Pre-flight storage & boot/ESP mount check before touching packages
  printf("\n");
  check_pacman_keyring();
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

  pre_upgrade_snapshot(0);

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

  // If a keyring update was detected in cached sync DBs, upgrade
  // archlinux-keyring first so new packager signatures don't fail the main
  // transaction.
  if (keyring_needs_update) {
    printf(CLR_CYAN "\n:: Refreshing archlinux-keyring before main "
                    "transaction...\n" CLR_RESET);
    char *const up_kr[] = {"sudo", "pacman", "-Sy", "--needed",
                           "--noconfirm", "archlinux-keyring", NULL};
    run_cmd(up_kr);
  }

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
  check_rebuilds();
  check_arch_audit();
  check_firmware_updates();

  print_step(&step, total_steps, "Sweeping orphaned dependencies...");
  sweep_orphans(aur_helper, auto_yes);

  print_step(&step, total_steps,
             has_flatpak ? "Cleaning caches (pacman/AUR: keep last 2 versions, "
                           "drop uninstalled; journal & Flatpak)..."
                         : "Cleaning caches (pacman/AUR: keep last 2 versions, "
                           "drop uninstalled; systemd journal)...");
  if (self_len > 0) {
    char *const sudo_cache[] = {"sudo", self_exe, "--clean-cache", NULL};
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
  check_hardware_health(0);

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

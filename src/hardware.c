#include "upgrade.h"

// Verifies that the filesystem backing `path` has at least `min_gib` GiB of
// unprivileged free space (f_bavail * f_frsize). Fails closed (-1) on error.
int check_disk_space(const char *path, double min_gib) {
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
int check_boot_mounts(int check_only) {
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

// ---- disk SMART health -----------------------------------------------------

struct smart_info {
  int seen;   // Any recognisable SMART output at all
  int health; // 1 = PASSED/OK, 0 = FAILED, -1 = unknown
  int wear_left;
  long long realloc_ct, pending, uncorr, crc, poh, media_err, temp;
  long long pct_used, spare, spare_thr, crit_warn;
};

static void parse_smart_output(const char *buf, struct smart_info *si) {
  memset(si, 0, sizeof(*si));
  si->health = -1;
  si->wear_left = -1;
  si->realloc_ct = si->pending = si->uncorr = si->crc = si->poh = -1;
  si->media_err = si->temp = si->pct_used = si->spare = -1;
  si->spare_thr = si->crit_warn = -1;

  for (const char *p = buf; *p != '\0';) {
    const char *nl = strchr(p, '\n');
    size_t len = nl ? (size_t)(nl - p) : strlen(p);
    char line[256];
    snprintf(line, sizeof(line), "%.*s", (int)len, p);
    p = nl ? nl + 1 : p + len;

    const char *v;
    long long n;

    if (strstr(line, "SMART overall-health self-assessment test result:")) {
      si->seen = 1;
      si->health = strstr(line, "PASSED") ? 1 : 0;
    } else if (strstr(line, "SMART Health Status:")) {
      si->seen = 1;
      si->health = strstr(line, "OK") ? 1 : 0;
    } else if ((v = line_after(line, "Critical Warning:"))) {
      const char *hx = strstr(v, "0x");
      si->crit_warn = hx ? (long long)strtol(hx, NULL, 16) : 0;
      si->seen = 1;
    } else if ((v = line_after(line, "Temperature:"))) {
      if (parse_first_int(v, &n))
        si->temp = n;
    } else if ((v = line_after(line, "Available Spare Threshold:"))) {
      if (parse_first_int(v, &n))
        si->spare_thr = n;
    } else if ((v = line_after(line, "Available Spare:"))) {
      if (parse_first_int(v, &n))
        si->spare = n;
    } else if ((v = line_after(line, "Percentage Used:"))) {
      if (parse_first_int(v, &n))
        si->pct_used = n;
    } else if ((v = line_after(line, "Power On Hours:"))) {
      if (parse_first_int(v, &n))
        si->poh = n;
    } else if ((v = line_after(line, "Media and Data Integrity Errors:"))) {
      if (parse_first_int(v, &n))
        si->media_err = n;
    } else {
      // ATA attribute table row:
      // ID NAME FLAG VALUE WORST THRESH TYPE UPDATED WHEN_FAILED RAW
      char name[64];
      int id;
      if (sscanf(line, " %d %63s", &id, name) != 2)
        continue;
      si->seen = 1;
      long long raw = 0, norm = 0;
      int has_raw = parse_first_int(skip_tokens(line, 9), &raw);
      int has_norm = parse_first_int(skip_tokens(line, 3), &norm);

      if (has_raw && strcmp(name, "Reallocated_Sector_Ct") == 0)
        si->realloc_ct = raw;
      else if (has_raw && strcmp(name, "Current_Pending_Sector") == 0)
        si->pending = raw;
      else if (has_raw && strcmp(name, "Offline_Uncorrectable") == 0)
        si->uncorr = raw;
      else if (has_raw && strcmp(name, "UDMA_CRC_Error_Count") == 0)
        si->crc = raw;
      else if (has_raw && strcmp(name, "Power_On_Hours") == 0)
        si->poh = raw;
      else if (has_raw && strcmp(name, "Temperature_Celsius") == 0)
        si->temp = raw;
      else if (has_raw && strcmp(name, "Airflow_Temperature_Cel") == 0 &&
               si->temp < 0)
        si->temp = raw;
      else if (has_norm && norm >= 0 && norm <= 100 &&
               (strcmp(name, "Wear_Leveling_Count") == 0 ||
                strcmp(name, "Media_Wearout_Indicator") == 0 ||
                strcmp(name, "SSD_Life_Left") == 0 ||
                strcmp(name, "Percent_Lifetime_Remain") == 0 ||
                strcmp(name, "Remaining_Lifetime_Perc") == 0))
        si->wear_left = (int)norm;
    }
  }
  // Some drives pack min/max into the raw temperature; the low byte is °C.
  if (si->temp > 150)
    si->temp &= 0xFF;
}

// Judges one disk's parsed SMART output and prints a one-line verdict plus
// any issues. `label` is e.g. "sda  Samsung SSD 860 (465 GB, SSD)".
static void report_disk(const char *label, int rotational, const char *out) {
  if (strstr(out, "STANDBY") || strstr(out, "SLEEP")) {
    printf(CLR_GREEN "[✓] %s: in standby (not woken for SMART).\n" CLR_RESET,
           label);
    return;
  }

  struct smart_info si;
  parse_smart_output(out, &si);

  if (!si.seen)
    return;

  int sev = 0; // 0 ok, 1 warn, 2 bad
  char issues[5][112];
  int ni = 0;
#define ISSUE(level, ...)                                                      \
  do {                                                                         \
    if ((level) > sev)                                                         \
      sev = (level);                                                           \
    if (ni < 5)                                                                \
      snprintf(issues[ni++], sizeof(issues[0]), __VA_ARGS__);                  \
  } while (0)

  if (si.health == 0)
    ISSUE(2, "SMART overall health FAILED — back up now, replace the drive");
  if (si.crit_warn > 0)
    ISSUE(2, "NVMe critical-warning flags set (0x%llx)", si.crit_warn);
  if (si.pending > 0)
    ISSUE(2, "%lld pending (unreadable) sectors", si.pending);
  if (si.uncorr > 0)
    ISSUE(2, "%lld offline-uncorrectable sectors", si.uncorr);
  if (si.realloc_ct > 0)
    ISSUE(si.realloc_ct >= 50 ? 2 : 1, "%lld reallocated sectors",
          si.realloc_ct);
  if (si.media_err > 0)
    ISSUE(2, "%lld media/data-integrity errors", si.media_err);
  if (si.crc > 0)
    ISSUE(1, "%lld interface CRC errors (check the SATA cable/port)", si.crc);
  if (si.spare >= 0 && si.spare_thr >= 0 && si.spare < si.spare_thr)
    ISSUE(2, "available spare %lld%% fell below the %lld%% threshold",
          si.spare, si.spare_thr);
  if (si.pct_used >= 95)
    ISSUE(2, "%lld%% of rated endurance used", si.pct_used);
  else if (si.pct_used >= 80)
    ISSUE(1, "%lld%% of rated endurance used", si.pct_used);
  if (si.wear_left >= 0 && si.wear_left <= 5)
    ISSUE(2, "only ~%d%% SSD life remaining", si.wear_left);
  else if (si.wear_left >= 0 && si.wear_left <= 20)
    ISSUE(1, "only ~%d%% SSD life remaining", si.wear_left);
  if (si.temp >= 0) {
    long long warn = rotational ? 50 : 70, bad = rotational ? 60 : 80;
    if (si.temp >= bad)
      ISSUE(2, "running very hot: %lld°C", si.temp);
    else if (si.temp >= warn)
      ISSUE(1, "running warm: %lld°C", si.temp);
  }
#undef ISSUE

  char t_temp[40] = "", t_poh[32] = "", t_wear[32] = "";
  if (si.temp >= 0)
    snprintf(t_temp, sizeof(t_temp), ", %lld°C", si.temp);
  if (si.poh >= 0)
    snprintf(t_poh, sizeof(t_poh), ", %lld h", si.poh);
  if (si.pct_used >= 0)
    snprintf(t_wear, sizeof(t_wear), ", %lld%% used", si.pct_used);
  else if (si.wear_left >= 0)
    snprintf(t_wear, sizeof(t_wear), ", %d%% life left", si.wear_left);

  const char *verdict = si.health == 1   ? "PASSED"
                        : si.health == 0 ? "FAILED"
                                         : "health n/a";
  if (sev == 0) {
    printf(CLR_GREEN "[✓] %s: %s%s%s%s\n" CLR_RESET, label, verdict, t_temp,
           t_poh, t_wear);
  } else {
    printf("%s[!] %s: %s%s%s%s\n" CLR_RESET, sev == 2 ? CLR_RED : CLR_YELLOW,
           label, verdict, t_temp, t_poh, t_wear);
    for (int i = 0; i < ni; i++)
      printf("      - %s\n", issues[i]);
  }
}

static int cmp_name32(const void *a, const void *b) {
  return strcmp((const char *)a, (const char *)b);
}

// Enumerates internal SATA/NVMe disks via /sys/block and runs `smartctl` on
// each (through `sudo -n`, which works during the upgrade because the sudo
// keep-alive is running; as plain -c it needs a cached sudo ticket).
static void check_disks_smart(void) {
  DIR *d = opendir("/sys/block");
  if (!d)
    return;

  char names[24][32];
  int count = 0;
  struct dirent *ent;
  while ((ent = readdir(d)) != NULL && count < 24) {
    const char *n = ent->d_name;
    if (strncmp(n, "sd", 2) != 0 && strncmp(n, "nvme", 4) != 0)
      continue;
    char path[PATH_MAX], rem[8] = "";
    snprintf(path, sizeof(path), "/sys/block/%s/removable", n);
    if (read_small_file(path, rem, sizeof(rem)) == 0 && rem[0] == '1')
      continue; // USB sticks / card readers
    snprintf(names[count++], sizeof(names[0]), "%.31s", n);
  }
  closedir(d);
  qsort(names, (size_t)count, sizeof(names[0]), cmp_name32);

  if (count == 0 || !have_cmd("smartctl"))
    return;

  int root = (geteuid() == 0);
  for (int i = 0; i < count; i++) {
    const char *name = names[i];
    char path[PATH_MAX], model[96] = "", rot[8] = "", sz_s[32] = "";

    snprintf(path, sizeof(path), "/sys/block/%s/device/model", name);
    read_small_file(path, model, sizeof(model));
    size_t ml = strlen(model);
    while (ml > 0 && model[ml - 1] == ' ')
      model[--ml] = '\0';

    snprintf(path, sizeof(path), "/sys/block/%s/queue/rotational", name);
    int rotational = (read_small_file(path, rot, sizeof(rot)) == 0 &&
                      rot[0] == '1');

    unsigned long long sectors = 0;
    snprintf(path, sizeof(path), "/sys/block/%s/size", name);
    if (read_small_file(path, sz_s, sizeof(sz_s)) == 0)
      sectors = strtoull(sz_s, NULL, 10);

    const char *type = strncmp(name, "nvme", 4) == 0 ? "NVMe"
                       : rotational                    ? "HDD"
                                                       : "SSD";
    char label[200];
    snprintf(label, sizeof(label), "%.31s  %s (%.0f GB, %s)", name,
             model[0] ? model : "unknown model",
             (double)sectors * 512.0 / 1e9, type);

    char dev[64];
    snprintf(dev, sizeof(dev), "/dev/%.31s", name);
    char *argv[10];
    int a = 0;
    if (!root) {
      argv[a++] = "sudo";
      argv[a++] = "-n";
    }
    argv[a++] = "smartctl";
    if (rotational) { // don't spin up sleeping HDDs just to read SMART
      argv[a++] = "-n";
      argv[a++] = "standby";
    }
    argv[a++] = "-H";
    argv[a++] = "-A";
    argv[a++] = dev;
    argv[a] = NULL;

    char out[16384];
    int rc = -1;
    if (capture_cmd_output(argv, out, sizeof(out), &rc) < 0)
      out[0] = '\0';
    report_disk(label, rotational, out);
  }
}

// ---- RAM health ------------------------------------------------------------

// Sums every `<dir>/mc*/<file>` counter under the EDAC sysfs tree.
static int edac_sum(const char *file, unsigned long long *total) {
  DIR *d = opendir("/sys/devices/system/edac/mc");
  if (!d)
    return -1;
  int controllers = 0;
  struct dirent *ent;
  while ((ent = readdir(d)) != NULL) {
    if (strncmp(ent->d_name, "mc", 2) != 0 ||
        !isdigit((unsigned char)ent->d_name[2]))
      continue;
    char path[PATH_MAX], val[32];
    snprintf(path, sizeof(path), "/sys/devices/system/edac/mc/%s/%s",
             ent->d_name, file);
    controllers++;
    if (read_small_file(path, val, sizeof(val)) == 0)
      *total += strtoull(val, NULL, 10);
  }
  closedir(d);
  return controllers;
}

// Compares DMI-reported installed DIMM capacity with what the kernel sees.
// A big gap usually means a module failed to train/map. Needs root.
static void check_dimm_inventory(unsigned long long mem_total_kb) {
  if (!have_cmd("dmidecode"))
    return;

  char out[65536];
  int rc = -1;
  ssize_t n;
  if (geteuid() == 0) {
    char *const cmd[] = {"dmidecode", "-t", "memory", NULL};
    n = capture_cmd_output(cmd, out, sizeof(out), &rc);
  } else {
    char *const cmd[] = {"sudo", "-n", "dmidecode", "-t", "memory", NULL};
    n = capture_cmd_output(cmd, out, sizeof(out), &rc);
  }
  if (n <= 0 || rc != 0)
    return;

  unsigned long long installed_mb = 0;
  int dimms = 0;
  for (const char *p = out; *p != '\0';) {
    const char *nl = strchr(p, '\n');
    size_t len = nl ? (size_t)(nl - p) : strlen(p);
    char line[160];
    snprintf(line, sizeof(line), "%.*s", (int)len, p);
    p = nl ? nl + 1 : p + len;

    const char *v = line_after(line, "Size:");
    long long sz;
    if (!v || !parse_first_int(v, &sz) || sz <= 0)
      continue; // "No Module Installed" etc.
    installed_mb += (strstr(v, "GB") || strstr(v, "GiB"))
                        ? (unsigned long long)sz * 1024ULL
                        : (unsigned long long)sz;
    dimms++;
  }
  if (dimms == 0 || installed_mb == 0)
    return;

  unsigned long long visible_mb = mem_total_kb / 1024ULL;
  if (visible_mb * 10ULL < installed_mb * 9ULL) {
    printf(CLR_YELLOW "[!] RAM: DMI lists %llu MiB in %d DIMM(s) but the "
                      "kernel only sees %llu MiB —\n"
                      "    a module may have failed to train/map (or the "
                      "firmware/iGPU reserves a lot).\n" CLR_RESET,
           installed_mb, dimms, visible_mb);
  } else {
    printf(CLR_GREEN "[✓] RAM: %llu MiB in %d DIMM(s) per DMI, %llu MiB "
                     "usable.\n" CLR_RESET,
           installed_mb, dimms, visible_mb);
  }
}

static void check_ram_health(void) {
  unsigned long long hw_corrupt_kb = 0, mem_total_kb = 0, swap_total_kb = 0,
                     swap_free_kb = 0;
  FILE *fp = fopen("/proc/meminfo", "r");
  if (fp) {
    char line[128];
    while (fgets(line, sizeof(line), fp)) {
      sscanf(line, "HardwareCorrupted: %llu kB", &hw_corrupt_kb);
      sscanf(line, "MemTotal: %llu kB", &mem_total_kb);
      sscanf(line, "SwapTotal: %llu kB", &swap_total_kb);
      sscanf(line, "SwapFree: %llu kB", &swap_free_kb);
    }
    fclose(fp);
  }

  int problems = 0;

  if (hw_corrupt_kb > 0) {
    printf(CLR_RED "[!] RAM: kernel has quarantined %llu kB of failing "
                   "memory (HardwareCorrupted).\n" CLR_RESET,
           hw_corrupt_kb);
    problems++;
  }

  unsigned long long ce = 0, ue = 0;
  int mcs = edac_sum("ce_count", &ce);
  edac_sum("ue_count", &ue);
  if (mcs > 0) {
    if (ue > 0) {
      printf(CLR_RED "[!] RAM ECC: %llu UNCORRECTABLE and %llu corrected "
                     "error(s) across %d controller(s).\n" CLR_RESET,
             ue, ce, mcs);
      problems++;
    } else if (ce > 0) {
      printf(CLR_YELLOW "[!] RAM ECC: %llu corrected error(s) across %d "
                        "controller(s) — a DIMM is degrading (find which with "
                        "`ras-mc-ctl --error-count`).\n" CLR_RESET,
             ce, mcs);
      problems++;
    } else {
      printf(CLR_GREEN "[✓] RAM ECC: 0 corrected / 0 uncorrectable errors "
                       "(%d controller(s)).\n" CLR_RESET,
             mcs);
    }
  }

  if (mem_total_kb > 0)
    check_dimm_inventory(mem_total_kb);

  // Check active zram compression ratio if zram0 is configured
  char zstat[256];
  if (read_small_file("/sys/block/zram0/mm_stat", zstat, sizeof(zstat)) == 0) {
    unsigned long long orig_b = 0, compr_b = 0, mem_used_b = 0;
    if (sscanf(zstat, "%llu %llu %llu", &orig_b, &compr_b, &mem_used_b) >= 2 &&
        orig_b > 1048576ULL && compr_b > 0) {
      double orig_mib = (double)orig_b / (1024.0 * 1024.0);
      double compr_mib = (double)compr_b / (1024.0 * 1024.0);
      printf(CLR_GREEN "[✓] ZRAM (zram0): %.1f MiB compressed to %.1f MiB "
                       "(%.2fx ratio).\n" CLR_RESET,
             orig_mib, compr_mib, (double)orig_b / (double)compr_b);
    }
  }

  if (swap_total_kb > 0) {
    unsigned long long used = swap_total_kb - swap_free_kb;
    if (used * 2ULL > swap_total_kb)
      printf(CLR_YELLOW "[!] Swap is %llu%% full — memory pressure or a "
                        "leak.\n" CLR_RESET,
             used * 100ULL / swap_total_kb);
  }

  if (problems > 0)
    printf(CLR_MAGENTA "    Confirm with a real test: boot memtest86+ "
                       "(pacman -S memtest86+-efi) — it can't run from a live "
                       "system.\n" CLR_RESET);
}

// ---- CPU thermals, governor & thermal throttling ---------------------------

static void check_cpu_thermals(void) {
  long max_millic = -1;
  char best_sensor[64] = "";

  // 1. Scan /sys/class/hwmon/hwmon* for CPU package temperature sensors
  DIR *hd = opendir("/sys/class/hwmon");
  if (hd) {
    struct dirent *ent;
    while ((ent = readdir(hd)) != NULL) {
      if (ent->d_name[0] == '.')
        continue;
      char name_path[PATH_MAX], sensor_name[64] = "";
      snprintf(name_path, sizeof(name_path), "/sys/class/hwmon/%s/name",
               ent->d_name);
      if (read_small_file(name_path, sensor_name, sizeof(sensor_name)) != 0)
        continue;
      if (strcmp(sensor_name, "coretemp") != 0 &&
          strcmp(sensor_name, "k10temp") != 0 &&
          strcmp(sensor_name, "zenpower") != 0 &&
          strcmp(sensor_name, "cpu_thermal") != 0 &&
          strcmp(sensor_name, "acpitz") != 0)
        continue;

      char tpath[PATH_MAX], tbuf[32];
      snprintf(tpath, sizeof(tpath), "/sys/class/hwmon/%s/temp1_input",
               ent->d_name);
      if (read_small_file(tpath, tbuf, sizeof(tbuf)) == 0) {
        long val = strtol(tbuf, NULL, 10);
        if (val > max_millic && val < 150000) {
          max_millic = val;
          snprintf(best_sensor, sizeof(best_sensor), "%s", sensor_name);
        }
      }
    }
    closedir(hd);
  }

  // 2. Fallback to /sys/class/thermal/thermal_zone*
  if (max_millic < 0) {
    DIR *td = opendir("/sys/class/thermal");
    if (td) {
      struct dirent *ent;
      while ((ent = readdir(td)) != NULL) {
        if (strncmp(ent->d_name, "thermal_zone", 12) != 0)
          continue;
        char tpath[PATH_MAX], tbuf[32];
        snprintf(tpath, sizeof(tpath), "/sys/class/thermal/%s/temp",
                 ent->d_name);
        if (read_small_file(tpath, tbuf, sizeof(tbuf)) == 0) {
          long val = strtol(tbuf, NULL, 10);
          if (val > max_millic && val < 150000) {
            max_millic = val;
            snprintf(best_sensor, sizeof(best_sensor), "%.63s", ent->d_name);
          }
        }
      }
      closedir(td);
    }
  }

  // 3. Check CPU thermal throttle counters across all cores
  unsigned long long throttle_events = 0;
  DIR *cd = opendir("/sys/devices/system/cpu");
  if (cd) {
    struct dirent *ent;
    while ((ent = readdir(cd)) != NULL) {
      if (strncmp(ent->d_name, "cpu", 3) != 0 ||
          !isdigit((unsigned char)ent->d_name[3]))
        continue;
      char cpath[PATH_MAX], cbuf[32];
      snprintf(cpath, sizeof(cpath),
               "/sys/devices/system/cpu/%s/thermal_throttle/core_throttle_count",
               ent->d_name);
      if (read_small_file(cpath, cbuf, sizeof(cbuf)) == 0)
        throttle_events += strtoull(cbuf, NULL, 10);
    }
    closedir(cd);
  }

  char gov[64] = "";
  read_small_file("/sys/devices/system/cpu/cpu0/cpufreq/scaling_governor", gov,
                  sizeof(gov));

  if (max_millic >= 0) {
    double degc = (double)max_millic / 1000.0;
    char gov_info[80] = "";
    if (gov[0] != '\0')
      snprintf(gov_info, sizeof(gov_info), ", governor: %s", gov);

    if (degc >= 90.0 || throttle_events > 0) {
      printf(CLR_YELLOW "[!] CPU thermals: %.1f°C (%s%s)%s\n" CLR_RESET, degc,
             best_sensor, gov_info,
             throttle_events > 0 ? " — thermal throttling detected!" : "");
      if (throttle_events > 0) {
        printf("      - %llu core thermal-throttle event(s) recorded this "
               "boot\n",
               throttle_events);
      }
    } else {
      printf(CLR_GREEN "[✓] CPU thermals: %.1f°C (%s%s), 0 throttle events.\n"
                       CLR_RESET,
             degc, best_sensor, gov_info);
    }
  }
}

static void check_gpu_thermals(void) {
  int reported = 0;

  DIR *hd = opendir("/sys/class/hwmon");
  if (hd) {
    struct dirent *ent;
    while ((ent = readdir(hd)) != NULL) {
      if (ent->d_name[0] == '.')
        continue;
      char name_path[PATH_MAX], sensor_name[64] = "";
      snprintf(name_path, sizeof(name_path), "/sys/class/hwmon/%s/name",
               ent->d_name);
      if (read_small_file(name_path, sensor_name, sizeof(sensor_name)) != 0)
        continue;
      if (strcmp(sensor_name, "amdgpu") != 0 &&
          strcmp(sensor_name, "radeon") != 0 &&
          strcmp(sensor_name, "nouveau") != 0)
        continue;

      char tpath[PATH_MAX], tbuf[32];
      snprintf(tpath, sizeof(tpath), "/sys/class/hwmon/%s/temp1_input",
               ent->d_name);
      if (read_small_file(tpath, tbuf, sizeof(tbuf)) != 0) {
        snprintf(tpath, sizeof(tpath), "/sys/class/hwmon/%s/temp2_input",
                 ent->d_name);
        if (read_small_file(tpath, tbuf, sizeof(tbuf)) != 0)
          continue;
      }
      long millic = strtol(tbuf, NULL, 10);
      if (millic <= 0 || millic >= 150000)
        continue;

      double degc = (double)millic / 1000.0;
      if (degc >= 95.0) {
        printf(CLR_RED "[!] GPU thermals: %.1f°C (%s — running very hot!)\n"
                       CLR_RESET,
               degc, sensor_name);
      } else if (degc >= 85.0) {
        printf(CLR_YELLOW "[!] GPU thermals: %.1f°C (%s — running warm)\n"
                          CLR_RESET,
               degc, sensor_name);
      } else {
        printf(CLR_GREEN "[✓] GPU thermals: %.1f°C (%s).\n" CLR_RESET, degc,
               sensor_name);
      }
      reported = 1;
    }
    closedir(hd);
  }

  if (!reported && have_cmd("nvidia-smi")) {
    char out[512];
    int rc = -1;
    char *const cmd[] = {"nvidia-smi",
                         "--query-gpu=name,temperature.gpu",
                         "--format=csv,noheader,nounits", NULL};
    if (capture_cmd_output(cmd, out, sizeof(out), &rc) > 0 && rc == 0) {
      for (const char *p = out; *p != '\0';) {
        const char *nl = strchr(p, '\n');
        size_t len = nl ? (size_t)(nl - p) : strlen(p);
        char line[160];
        snprintf(line, sizeof(line), "%.*s", (int)len, p);
        p = nl ? nl + 1 : p + len;

        char *comma = strrchr(line, ',');
        if (!comma)
          continue;
        *comma = '\0';
        long long degc = 0;
        if (!parse_first_int(comma + 1, &degc))
          continue;
        if (degc >= 95) {
          printf(CLR_RED "[!] GPU thermals: %lld°C (%s — running very hot!)\n"
                         CLR_RESET,
                 degc, line);
        } else if (degc >= 85) {
          printf(CLR_YELLOW "[!] GPU thermals: %lld°C (%s — running warm)\n"
                            CLR_RESET,
                 degc, line);
        } else {
          printf(CLR_GREEN "[✓] GPU thermals: %lld°C (%s).\n" CLR_RESET, degc,
                 line);
        }
      }
    }
  }
}

// ---- ext4 superblock errors, mdadm RAID & laptop battery health ------------

static void check_fs_raid_battery(int check_only) {
  // 1. Check /sys/fs/ext4/*/errors_count for persistent filesystem corruption
  DIR *ed = opendir("/sys/fs/ext4");
  if (ed) {
    struct dirent *ent;
    while ((ent = readdir(ed)) != NULL) {
      if (ent->d_name[0] == '.' || strcmp(ent->d_name, "features") == 0)
        continue;
      char epath[PATH_MAX], ebuf[32];
      snprintf(epath, sizeof(epath), "/sys/fs/ext4/%s/errors_count",
               ent->d_name);
      if (read_small_file(epath, ebuf, sizeof(ebuf)) == 0) {
        unsigned long long errs = strtoull(ebuf, NULL, 10);
        if (errs > 0) {
          printf(CLR_RED "[!] Filesystem ext4 (%s): %llu superblock error(s) "
                         "recorded — schedule an offline `fsck`!\n" CLR_RESET,
                 ent->d_name, errs);
        }
      }
    }
    closedir(ed);
  }

  // 2. Check /proc/mdstat for degraded software RAID arrays
  FILE *md = fopen("/proc/mdstat", "r");
  if (md) {
    char line[256];
    char cur_md[64] = "";
    while (fgets(line, sizeof(line), md)) {
      if (strncmp(line, "md", 2) == 0 && strstr(line, " : active")) {
        sscanf(line, "%63s", cur_md);
      } else if (cur_md[0] != '\0' && strchr(line, '[') && strchr(line, ']')) {
        const char *lb = strrchr(line, '[');
        const char *rb = lb ? strchr(lb, ']') : NULL;
        if (lb && rb && rb > lb + 1) {
          int degraded = 0;
          for (const char *p = lb + 1; p < rb; p++) {
            if (*p == '_')
              degraded = 1;
          }
          if (degraded) {
            printf(CLR_RED "[!] RAID array %s is DEGRADED (%.*s) — check "
                           "`cat /proc/mdstat`!\n" CLR_RESET,
                   cur_md, (int)(rb - lb + 1), lb);
          } else {
            printf(CLR_GREEN "[✓] RAID array %s: healthy (%.*s).\n" CLR_RESET,
                   cur_md, (int)(rb - lb + 1), lb);
          }
        }
        cur_md[0] = '\0';
      }
    }
    fclose(md);
  }

  // 3. Check laptop battery health & charge level via /sys/class/power_supply
  DIR *pd = opendir("/sys/class/power_supply");
  if (pd) {
    struct dirent *ent;
    while ((ent = readdir(pd)) != NULL) {
      if (strncmp(ent->d_name, "BAT", 3) != 0)
        continue;
      char bpath[PATH_MAX], status[32] = "", cap_s[32] = "";
      snprintf(bpath, sizeof(bpath), "/sys/class/power_supply/%s/status",
               ent->d_name);
      read_small_file(bpath, status, sizeof(status));

      snprintf(bpath, sizeof(bpath), "/sys/class/power_supply/%s/capacity",
               ent->d_name);
      int cap = -1;
      if (read_small_file(bpath, cap_s, sizeof(cap_s)) == 0)
        cap = atoi(cap_s);

      char full_s[32] = "", design_s[32] = "";
      snprintf(bpath, sizeof(bpath), "/sys/class/power_supply/%s/energy_full",
               ent->d_name);
      if (read_small_file(bpath, full_s, sizeof(full_s)) == 0) {
        snprintf(bpath, sizeof(bpath),
                 "/sys/class/power_supply/%s/energy_full_design", ent->d_name);
        read_small_file(bpath, design_s, sizeof(design_s));
      } else {
        snprintf(bpath, sizeof(bpath), "/sys/class/power_supply/%s/charge_full",
                 ent->d_name);
        if (read_small_file(bpath, full_s, sizeof(full_s)) == 0) {
          snprintf(bpath, sizeof(bpath),
                   "/sys/class/power_supply/%s/charge_full_design",
                   ent->d_name);
          read_small_file(bpath, design_s, sizeof(design_s));
        }
      }

      double health_pct = -1.0;
      unsigned long long full_v = strtoull(full_s, NULL, 10);
      unsigned long long design_v = strtoull(design_s, NULL, 10);
      if (full_v > 0 && design_v > 0)
        health_pct = ((double)full_v / (double)design_v) * 100.0;

      char health_str[48] = "";
      if (health_pct > 0.0 && health_pct <= 150.0)
        snprintf(health_str, sizeof(health_str), ", %.0f%% battery health",
                 health_pct);

      if (!check_only && strcmp(status, "Discharging") == 0 && cap >= 0 &&
          cap < 20) {
        printf(CLR_RED "[!] Battery %s: %d%% (Discharging%s) — plug in AC "
                       "power to avoid power loss during upgrade!\n" CLR_RESET,
               ent->d_name, cap, health_str);
      } else if (cap >= 0) {
        printf(CLR_GREEN "[✓] Battery %s: %d%% (%s%s).\n" CLR_RESET,
               ent->d_name, cap, status[0] ? status : "ok", health_str);
      }
    }
    closedir(pd);
  }

  // 4. Check Btrfs device I/O & corruption stats (deduplicated by dev major:minor)
  if (have_cmd("btrfs")) {
    FILE *mp = fopen("/proc/self/mountinfo", "r");
    if (mp) {
      char seen_devs[16][32];
      int seen_cnt = 0;
      char line[1024];
      while (fgets(line, sizeof(line), mp)) {
        char devid[32], mnt[512], fstype[64];
        if (sscanf(line, "%*s %*s %31s %*s %511s", devid, mnt) != 2)
          continue;
        const char *sep = strstr(line, " - ");
        if (!sep || sscanf(sep + 3, "%63s", fstype) != 1 ||
            strcmp(fstype, "btrfs") != 0)
          continue;

        int dup = 0;
        for (int i = 0; i < seen_cnt; i++) {
          if (strcmp(seen_devs[i], devid) == 0) {
            dup = 1;
            break;
          }
        }
        if (dup || seen_cnt >= 16)
          continue;
        snprintf(seen_devs[seen_cnt++], sizeof(seen_devs[0]), "%s", devid);

        char bout[4096];
        int brc = -1;
        ssize_t bn;
        if (geteuid() == 0) {
          char *const bcmd[] = {"btrfs", "device", "stats", mnt, NULL};
          bn = capture_cmd_output(bcmd, bout, sizeof(bout), &brc);
        } else {
          char *const bcmd[] = {"sudo", "-n", "btrfs", "device", "stats", mnt,
                                NULL};
          bn = capture_cmd_output(bcmd, bout, sizeof(bout), &brc);
        }
        if (bn <= 0 || brc != 0)
          continue;

        unsigned long long errs = 0;
        for (const char *p = bout; *p != '\0';) {
          const char *nl = strchr(p, '\n');
          size_t len = nl ? (size_t)(nl - p) : strlen(p);
          char bline[256];
          snprintf(bline, sizeof(bline), "%.*s", (int)len, p);
          p = nl ? nl + 1 : p + len;

          if (strstr(bline, "_errs")) {
            const char *sp = strrchr(bline, ' ');
            if (sp)
              errs += strtoull(sp + 1, NULL, 10);
          }
        }
        if (errs > 0) {
          printf(CLR_RED "[!] Filesystem btrfs (%s): %llu device/corruption "
                         "error(s) — run `btrfs device stats %s`!\n" CLR_RESET,
                 mnt, errs, mnt);
        } else {
          printf(CLR_GREEN "[✓] Filesystem btrfs (%s): 0 device I/O or "
                           "corruption errors.\n" CLR_RESET,
                 mnt);
        }
      }
      fclose(mp);
    }
  }

  // 5. Check fstrim.timer when non-rotational disks exist without `discard`
  if (check_only && access("/run/systemd/system", F_OK) == 0 &&
      have_cmd("systemctl")) {
    int has_ssd = 0;
    DIR *bd = opendir("/sys/block");
    if (bd) {
      struct dirent *ent;
      while ((ent = readdir(bd)) != NULL) {
        if (strncmp(ent->d_name, "nvme", 4) != 0 &&
            strncmp(ent->d_name, "sd", 2) != 0)
          continue;
        char rpath[PATH_MAX], rot[8] = "";
        snprintf(rpath, sizeof(rpath), "/sys/block/%s/queue/rotational",
                 ent->d_name);
        if (read_small_file(rpath, rot, sizeof(rot)) == 0 && rot[0] == '0') {
          has_ssd = 1;
          break;
        }
      }
      closedir(bd);
    }

    int has_discard = 0;
    FILE *mp = fopen("/proc/self/mountinfo", "r");
    if (mp) {
      char line[1024];
      while (fgets(line, sizeof(line), mp)) {
        if (strstr(line, "discard")) {
          has_discard = 1;
          break;
        }
      }
      fclose(mp);
    }

    if (has_ssd && !has_discard) {
      char dummy[64];
      int trc = -1;
      char *const tcmd[] = {"systemctl", "is-enabled", "--quiet",
                            "fstrim.timer", NULL};
      capture_cmd_output(tcmd, dummy, sizeof(dummy), &trc);
      if (trc != 0) {
        printf(CLR_MAGENTA "[i] SSD detected without fstrim.timer enabled "
                           "(enable with `sudo systemctl enable --now "
                           "fstrim.timer`).\n" CLR_RESET);
      }
    }
  }
}

// ---- kernel log: storage / filesystem / machine-check / OOM -----------------

static void check_kernel_hw_errors(int check_only) {
  if (!have_cmd("journalctl"))
    return;

  const size_t cap = 262144;
  char *buf = malloc(cap);
  if (!buf)
    return;
  int rc = -1;
  char *const cmd[] = {"journalctl", "-k", "-b",    "-p", "err", "-o",
                       "cat",        "--no-pager", "-n", "4000", NULL};
  ssize_t got = capture_cmd_output(cmd, buf, cap, &rc);
  if ((got < 0 || rc != 0) && !check_only && geteuid() != 0) {
    char *const scmd[] = {"sudo",       "-n", "journalctl", "-k", "-b", "-p",
                          "err",        "-o", "cat", "--no-pager", "-n", "4000",
                          NULL};
    got = capture_cmd_output(scmd, buf, cap, &rc);
  }
  if (got < 0 || rc != 0) {
    free(buf);
    return;
  }

  enum { K_DISK, K_FS, K_MCE, K_OOM, K_N };
  size_t cnt[K_N] = {0};
  char sample[K_N][176] = {{0}};

  for (const char *p = buf; *p != '\0';) {
    const char *nl = strchr(p, '\n');
    size_t len = nl ? (size_t)(nl - p) : strlen(p);
    char line[512];
    snprintf(line, sizeof(line), "%.*s", (int)len, p);
    p = nl ? nl + 1 : p + len;

    int k = -1;
    if (strstr(line, "Machine check") || strstr(line, "mce:") ||
        strstr(line, "Hardware Error") || strstr(line, "Memory failure:") ||
        (strstr(line, "EDAC") && strstr(line, "error")))
      k = K_MCE;
    else if (strstr(line, "I/O error") || strstr(line, "blk_update_request") ||
             strstr(line, "exception Emask") ||
             strstr(line, "failed command:") ||
             (strstr(line, "nvme") &&
              (strstr(line, "timeout") || strstr(line, "controller is down"))))
      k = K_DISK;
    else if (strstr(line, "EXT4-fs error") || strstr(line, "BTRFS error") ||
             strstr(line, "csum failed") || strstr(line, "XFS") ||
             strstr(line, "corruption detected"))
      k = K_FS;
    else if (strstr(line, "Out of memory") || strstr(line, "oom-kill:"))
      k = K_OOM;

    if (k < 0)
      continue;
    if (cnt[k]++ == 0)
      snprintf(sample[k], sizeof(sample[k]), "%.170s", line);
  }
  free(buf);

  static const char *const what[K_N] = {
      "storage I/O error line(s)", "filesystem error line(s)",
      "machine-check / memory-error line(s)", "out-of-memory kill line(s)"};
  static const int severe[K_N] = {1, 1, 1, 0};
  int any = 0;
  for (int k = 0; k < K_N; k++) {
    if (cnt[k] == 0)
      continue;
    any = 1;
    printf("%s[!] Kernel logged %zu %s this boot:\n" CLR_RESET,
           severe[k] ? CLR_RED : CLR_YELLOW, cnt[k], what[k]);
    printf("      e.g. %s\n", sample[k]);
    printf("      (journalctl -k -b -p err)\n");
  }
  if (!any)
    printf(CLR_GREEN "[✓] Kernel log: no storage, filesystem, machine-check "
                     "or OOM errors this boot.\n" CLR_RESET);
}

void check_hardware_health(int check_only) {
  printf(CLR_CYAN "\n:: Hardware health (disks, memory, thermals, kernel "
                  "log)...\n" CLR_RESET);
  check_disks_smart();
  check_ram_health();
  check_cpu_thermals();
  check_gpu_thermals();
  check_fs_raid_battery(check_only);
  check_kernel_hw_errors(check_only);
}


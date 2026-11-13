#include "upgrade.h"

static void check_core_pkg_reboot_hints(const char *kver) {
  static const char *const core_pkgs[] = {
      "systemd",       "glibc",       "dbus",       "dbus-broker",
      "linux-firmware", "amd-ucode",  "intel-ucode", "mesa",
      "nvidia",        "nvidia-dkms", "nvidia-open", "nvidia-open-dkms",
      "cryptsetup",    "mkinitcpio",  "wayland",     "xorg-server"};
  struct sysinfo si;
  if (sysinfo(&si) != 0) {
    printf(CLR_GREEN "\n[✓] Kernel modules intact (%s) — no immediate reboot "
                     "required.\n" CLR_RESET,
           kver);
    return;
  }
  time_t boot_ts = time(NULL) - (time_t)si.uptime;

  FILE *fp = fopen("/var/log/pacman.log", "r");
  struct str_vec hits = {NULL, 0, 0};
  if (fp) {
    if (fseek(fp, 0, SEEK_END) == 0) {
      long end = ftell(fp);
      if (end > 262144) {
        fseek(fp, end - 262144, SEEK_SET);
        char discard[512];
        if (!fgets(discard, sizeof(discard), fp)) {
          fclose(fp);
          fp = NULL;
        }
      } else {
        rewind(fp);
      }
    }
    if (fp) {
      char line[512];
      while (fgets(line, sizeof(line), fp)) {
        time_t ts = 0;
        if (parse_pacman_log_ts(line, &ts) != 0 || ts < boot_ts)
          continue;
        const char *up = strstr(line, "[ALPM] upgraded ");
        if (!up)
          continue;
        const char *pkg = up + 16;
        char name[128];
        size_t ni = 0;
        while (pkg[ni] != '\0' && pkg[ni] != ' ' && pkg[ni] != '\t' &&
               ni + 1 < sizeof(name)) {
          name[ni] = pkg[ni];
          ni++;
        }
        name[ni] = '\0';
        for (size_t i = 0; i < sizeof(core_pkgs) / sizeof(core_pkgs[0]); i++) {
          if (strcmp(name, core_pkgs[i]) == 0) {
            str_vec_add_unique(&hits, name);
            break;
          }
        }
      }
      fclose(fp);
    }
  }

  if (hits.count > 0) {
    printf(CLR_YELLOW "\n[!] Core package(s) upgraded since boot (");
    for (size_t i = 0; i < hits.count; i++)
      printf("%s%s", i == 0 ? "" : ", ", hits.items[i]);
    printf(") — reboot recommended when convenient.\n" CLR_RESET);
  } else {
    printf(CLR_GREEN "\n[✓] Kernel modules intact (%s) — no immediate reboot "
                     "required.\n" CLR_RESET,
           kver);
  }
  str_vec_free(&hits);
}

// Checks whether the currently running kernel's module directory
// (/lib/modules/$(uname -r)) still exists on disk. On Arch Linux, upgrading
// the `linux` package removes the old kernel's modules immediately, meaning a
// reboot is needed before loading new kernel modules.
void check_kernel_reboot(void) {
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
    check_core_pkg_reboot_hints(uts.release);
  }
}

// Scans /proc/<pid>/exe and /proc/<pid>/maps for processes that are still
// running a deleted executable or holding deleted /usr/lib/*.so shared
// libraries in RAM after an upgrade, deduplicating by /proc/<pid>/comm.
void check_stale_libs(void) {
  DIR *proc = opendir("/proc");
  if (!proc)
    return;

  struct dirent *ent;
  int stale_count = 0;
  pid_t self = getpid();
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
      if (!fp)
        continue;

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
        printf(CLR_YELLOW "\n[!] Apps still running an older version "
                          "(restart when convenient):\n" CLR_RESET);
      }
      printf("    - %s\n", comm);
      stale_count++;
    }
  }
  closedir(proc);

  if (stale_count == 0) {
    printf(CLR_GREEN "[✓] All running apps are up to date.\n" CLR_RESET);
  }
}

static void norm_hex4(const char *raw, char out[5]) {
  const char *p = raw;
  if (p[0] == '0' && (p[1] == 'x' || p[1] == 'X'))
    p += 2;
  size_t i = 0;
  for (; i < 4 && isxdigit((unsigned char)p[i]); i++)
    out[i] = (char)tolower((unsigned char)p[i]);
  out[i] = '\0';
}

static const char *short_pci_vendor(const char *ven4) {
  if (strcmp(ven4, "1002") == 0)
    return "AMD";
  if (strcmp(ven4, "10de") == 0)
    return "NVIDIA";
  if (strcmp(ven4, "8086") == 0)
    return "Intel";
  if (strcmp(ven4, "1af4") == 0)
    return "VirtIO";
  if (strcmp(ven4, "15ad") == 0)
    return "VMware";
  if (strcmp(ven4, "1234") == 0)
    return "QEMU";
  return NULL;
}

static void lookup_pci_names(const char *ven4, const char *dev4, char *ven_out,
                             size_t ven_sz, char *dev_out, size_t dev_sz) {
  ven_out[0] = '\0';
  dev_out[0] = '\0';
  const char *sv = short_pci_vendor(ven4);
  if (sv)
    snprintf(ven_out, ven_sz, "%s", sv);

  FILE *fp = fopen("/usr/share/hwdata/pci.ids", "r");
  if (!fp)
    return;

  char line[512];
  int in_vendor = 0;
  while (fgets(line, sizeof(line), fp)) {
    if (line[0] == '#' || line[0] == '\n' || line[0] == '\r')
      continue;
    if (!in_vendor) {
      if (line[0] != '\t' && strncmp(line, ven4, 4) == 0 && line[4] == ' ') {
        in_vendor = 1;
        if (ven_out[0] == '\0') {
          const char *vn = line + 5;
          while (*vn == ' ')
            vn++;
          snprintf(ven_out, ven_sz, "%.*s", (int)(ven_sz - 1), vn);
          ven_out[strcspn(ven_out, "\r\n")] = '\0';
        }
      }
    } else {
      if (line[0] != '\t')
        break;
      if (line[1] != '\t' && strncmp(line + 1, dev4, 4) == 0 &&
          line[5] == ' ') {
        const char *dn = line + 6;
        while (*dn == ' ')
          dn++;
        snprintf(dev_out, dev_sz, "%.*s", (int)(dev_sz - 1), dn);
        dev_out[strcspn(dev_out, "\r\n")] = '\0';
        break;
      }
    }
  }
  fclose(fp);
}

static void detect_gpu_summary(char *out, size_t out_sz) {
  out[0] = '\0';
  DIR *d = opendir("/sys/class/drm");
  if (!d)
    return;

  size_t pos = 0;
  int gpu_cnt = 0;
  struct dirent *ent;
  while ((ent = readdir(d)) != NULL && gpu_cnt < 2) {
    if (strncmp(ent->d_name, "card", 4) != 0 ||
        !isdigit((unsigned char)ent->d_name[4]) ||
        strchr(ent->d_name, '-') != NULL)
      continue;

    char vpath[PATH_MAX], dpath[PATH_MAX], drpath[PATH_MAX];
    char vraw[32] = "", draw[32] = "", drv[64] = "";
    snprintf(vpath, sizeof(vpath), "/sys/class/drm/%s/device/vendor",
             ent->d_name);
    snprintf(dpath, sizeof(dpath), "/sys/class/drm/%s/device/device",
             ent->d_name);
    snprintf(drpath, sizeof(drpath), "/sys/class/drm/%s/device/driver",
             ent->d_name);

    char linkbuf[PATH_MAX];
    ssize_t llen = readlink(drpath, linkbuf, sizeof(linkbuf) - 1);
    if (llen > 0) {
      linkbuf[llen] = '\0';
      const char *base = strrchr(linkbuf, '/');
      snprintf(drv, sizeof(drv), "%.63s", base ? base + 1 : linkbuf);
    }

    char ven4[5] = "", dev4[5] = "";
    if (read_small_file(vpath, vraw, sizeof(vraw)) == 0)
      norm_hex4(vraw, ven4);
    if (read_small_file(dpath, draw, sizeof(draw)) == 0)
      norm_hex4(draw, dev4);

    if (ven4[0] == '\0' && drv[0] == '\0')
      continue;

    char ven_name[96] = "", dev_name[160] = "";
    if (strlen(ven4) == 4 && strlen(dev4) == 4)
      lookup_pci_names(ven4, dev4, ven_name, sizeof(ven_name), dev_name,
                       sizeof(dev_name));

    char entry[352];
    if (ven_name[0] && dev_name[0] && drv[0])
      snprintf(entry, sizeof(entry), "%s %s (%s)", ven_name, dev_name, drv);
    else if (ven_name[0] && dev_name[0])
      snprintf(entry, sizeof(entry), "%s %s", ven_name, dev_name);
    else if (ven_name[0] && drv[0])
      snprintf(entry, sizeof(entry), "%s [%s] (%s)", ven_name, dev4, drv);
    else if (drv[0])
      snprintf(entry, sizeof(entry), "%s", drv);
    else
      continue;

    if (pos + 4 >= out_sz)
      break;
    int max_w = (int)(out_sz - pos - (gpu_cnt == 0 ? 1 : 3));
    int w = snprintf(out + pos, out_sz - pos, "%s%.*s", gpu_cnt == 0 ? "" : ", ",
                     max_w, entry);
    if (w > 0 && pos + (size_t)w < out_sz)
      pos += (size_t)w;
    gpu_cnt++;
  }
  closedir(d);
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
void print_sys_summary(void) {
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

  // Memory & swap usage from /proc/meminfo
  unsigned long long mem_total_kb = 0, mem_avail_kb = 0;
  unsigned long long swap_total_kb = 0, swap_free_kb = 0;
  FILE *mem_fp = fopen("/proc/meminfo", "r");
  if (mem_fp) {
    char line[128];
    while (fgets(line, sizeof(line), mem_fp)) {
      sscanf(line, "MemTotal: %llu kB", &mem_total_kb);
      sscanf(line, "MemAvailable: %llu kB", &mem_avail_kb);
      sscanf(line, "SwapTotal: %llu kB", &swap_total_kb);
      sscanf(line, "SwapFree: %llu kB", &swap_free_kb);
      if (mem_total_kb && mem_avail_kb && swap_total_kb && swap_free_kb)
        break;
    }
    fclose(mem_fp);
  }

  char gpu_info[256];
  detect_gpu_summary(gpu_info, sizeof(gpu_info));

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
  size_t snap_pkgs = 0;
  DIR *sd = opendir("/var/lib/snapd/snap");
  if (!sd)
    sd = opendir("/snap");
  if (sd) {
    struct dirent *sent;
    while ((sent = readdir(sd)) != NULL) {
      if (sent->d_name[0] != '.' && strcmp(sent->d_name, "bin") != 0 &&
          strcmp(sent->d_name, "README") != 0)
        snap_pkgs++;
    }
    closedir(sd);
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

  if (gpu_info[0] != '\0')
    printf("   " CLR_CYAN "%-10s" CLR_RESET " %s\n", "GPU", gpu_info);

  if (mem_total_kb > 0) {
    double tot = (double)mem_total_kb / (1024.0 * 1024.0);
    double used = (double)(mem_total_kb - mem_avail_kb) / (1024.0 * 1024.0);
    printf("   " CLR_CYAN "%-10s" CLR_RESET " %.2f / %.2f GiB (%.0f%%)\n",
           "Memory", used, tot, (used / tot) * 100.0);
  }
  if (swap_total_kb > 0) {
    double stot = (double)swap_total_kb / (1024.0 * 1024.0);
    double sused = (double)(swap_total_kb - swap_free_kb) / (1024.0 * 1024.0);
    printf("   " CLR_CYAN "%-10s" CLR_RESET " %.2f / %.2f GiB (%.0f%%)\n",
           "Swap", sused, stot, (sused / stot) * 100.0);
  }

  struct statvfs vfs;
  if (statvfs("/", &vfs) == 0 && vfs.f_blocks > 0) {
    double tot = ((double)vfs.f_blocks * (double)vfs.f_frsize) /
                 (1024.0 * 1024.0 * 1024.0);
    double avail = ((double)vfs.f_bavail * (double)vfs.f_frsize) /
                   (1024.0 * 1024.0 * 1024.0);
    double used = tot - ((double)vfs.f_bfree * (double)vfs.f_frsize) /
                            (1024.0 * 1024.0 * 1024.0);
    printf("   " CLR_CYAN "%-10s" CLR_RESET
           " %.2f / %.2f GiB used (%.2f GiB free)\n",
           "Disk (/)", used, tot, avail);
  }

  double pkg_gib = (double)pacman_bytes / (1024.0 * 1024.0 * 1024.0);
  printf("   " CLR_CYAN "%-10s" CLR_RESET " %zu (pacman, %.2f GiB)",
         "Packages", pacman_pkgs, pkg_gib);
  if (flatpak_pkgs > 0)
    printf(", %zu (flatpak)", flatpak_pkgs);
  if (snap_pkgs > 0)
    printf(", %zu (snap)", snap_pkgs);
  putchar('\n');
}

off_t get_pacman_log_offset(void) {
  struct stat st;
  if (stat("/var/log/pacman.log", &st) != 0)
    return -1;
  return st.st_size;
}

static int is_notable_pkg(const char *pkg) {
  static const char *const notable[] = {
      "linux",          "linux-lts",     "linux-zen",      "linux-hardened",
      "linux-cachyos",  "systemd",       "glibc",          "pacman",
      "mesa",           "nvidia",        "nvidia-dkms",    "nvidia-open",
      "nvidia-open-dkms", "dbus",        "dbus-broker",    "linux-firmware",
      "amd-ucode",      "intel-ucode",   "cryptsetup",     "mkinitcpio"};
  for (size_t i = 0; i < sizeof(notable) / sizeof(notable[0]); i++) {
    if (strcmp(pkg, notable[i]) == 0)
      return 1;
  }
  return 0;
}

void parse_pacman_log_delta_buf(const char *buf, struct tx_summary *out) {
  memset(out, 0, sizeof(*out));
  if (!buf)
    return;

  struct str_vec notable_vec = {NULL, 0, 0};
  const char *p = buf;
  while (*p != '\0') {
    const char *nl = strchr(p, '\n');
    size_t len = nl ? (size_t)(nl - p) : strlen(p);
    char line[512];
    if (len > 0) {
      snprintf(line, sizeof(line), "%.*s",
               len >= sizeof(line) ? (int)sizeof(line) - 1 : (int)len, p);
      const char *alpm = strstr(line, "[ALPM] ");
      if (alpm) {
        const char *act = alpm + 7;
        const char *pkg = NULL;
        if (strncmp(act, "upgraded ", 9) == 0) {
          out->upgraded++;
          pkg = act + 9;
        } else if (strncmp(act, "installed ", 10) == 0) {
          out->installed++;
          pkg = act + 10;
        } else if (strncmp(act, "removed ", 8) == 0) {
          out->removed++;
          pkg = act + 8;
        }
        if (pkg) {
          char name[128];
          size_t ni = 0;
          while (pkg[ni] != '\0' && pkg[ni] != ' ' && pkg[ni] != '\t' &&
                 ni + 1 < sizeof(name)) {
            name[ni] = pkg[ni];
            ni++;
          }
          name[ni] = '\0';
          if (name[0] != '\0' && is_notable_pkg(name))
            str_vec_add_unique(&notable_vec, name);
        }
      }
    }
    if (!nl)
      break;
    p = nl + 1;
  }

  size_t pos = 0;
  for (size_t i = 0; i < notable_vec.count; i++) {
    int w = snprintf(out->notable + pos, sizeof(out->notable) - pos, "%s%s",
                     i == 0 ? "" : ", ", notable_vec.items[i]);
    if (w < 0 || pos + (size_t)w >= sizeof(out->notable))
      break;
    pos += (size_t)w;
  }
  str_vec_free(&notable_vec);
}

void summarize_pacman_log_delta(off_t start_offset, struct tx_summary *out) {
  memset(out, 0, sizeof(*out));
  if (start_offset < 0)
    return;

  FILE *fp = fopen("/var/log/pacman.log", "r");
  if (!fp)
    return;
  if (fseeko(fp, start_offset, SEEK_SET) != 0) {
    fclose(fp);
    return;
  }

  size_t cap = 4096, used = 0;
  char *buf = malloc(cap);
  if (!buf) {
    fclose(fp);
    return;
  }
  size_t n;
  while ((n = fread(buf + used, 1, cap - used - 1, fp)) > 0) {
    used += n;
    if (cap - used <= 1) {
      if (cap >= 4U * 1024U * 1024U)
        break;
      char *tmp = realloc(buf, cap * 2);
      if (!tmp)
        break;
      buf = tmp;
      cap *= 2;
    }
  }
  buf[used] = '\0';
  fclose(fp);

  parse_pacman_log_delta_buf(buf, out);
  free(buf);

  if (out->upgraded + out->installed + out->removed > 0) {
    printf(CLR_GREEN "\n[✓] Transaction summary: %zu upgraded, %zu installed, "
                     "%zu removed.\n" CLR_RESET,
           out->upgraded, out->installed, out->removed);
    if (out->notable[0] != '\0')
      printf("    Notable core packages: %s\n", out->notable);
  }
}

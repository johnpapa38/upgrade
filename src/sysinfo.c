#include "upgrade.h"

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
    printf(CLR_GREEN "\n[✓] Kernel modules intact (%s) — no immediate reboot "
                     "required.\n" CLR_RESET,
           uts.release);
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
  if (flatpak_pkgs > 0) {
    printf("   " CLR_CYAN "%-10s" CLR_RESET
           " %zu (pacman, %.2f GiB), %zu (flatpak)\n",
           "Packages", pacman_pkgs, pkg_gib, flatpak_pkgs);
  } else {
    printf("   " CLR_CYAN "%-10s" CLR_RESET " %zu (pacman, %.2f GiB)\n",
           "Packages", pacman_pkgs, pkg_gib);
  }
}

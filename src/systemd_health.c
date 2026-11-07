#include "upgrade.h"

static const char *systemd_exit_tag(int status) {
  switch (status) {
  case 200:
    return "200/CHDIR";
  case 203:
    return "203/EXEC";
  case 217:
    return "217/USER";
  case 218:
    return "218/CAPABILITIES";
  case 219:
    return "219/CGROUP";
  case 226:
    return "226/NAMESPACE";
  default:
    return NULL;
  }
}

static int is_systemd_boilerplate_log(const char *line) {
  if (strncmp(line, "Started ", 8) == 0 || strncmp(line, "Starting ", 9) == 0 ||
      strncmp(line, "Stopped ", 8) == 0 || strncmp(line, "Stopping ", 9) == 0)
    return 1;
  if (strstr(line, ": Scheduled restart job") ||
      strstr(line, ": Main process exited,") ||
      strstr(line, ": Failed with result ") || strstr(line, ": Consumed ") ||
      strstr(line, ": Failed at step EXEC spawning "))
    return 1;
  return 0;
}

// Inspects each failing or crash-looping unit via `systemctl show` and
// `journalctl` to explain *why* it is failing and print a concrete fix hint.
static void trace_systemd_units(const char *list_buf, int is_user) {
  const char *scope_flag = is_user ? " --user" : "";
  const char *cur = list_buf;

  while (*cur != '\0') {
    const char *nl = strchr(cur, '\n');
    size_t llen = nl ? (size_t)(nl - cur) : strlen(cur);

    // Extract first whitespace-delimited token (unit name)
    const char *s = cur;
    const char *end = cur + llen;
    while (s < end && (*s == ' ' || *s == '\t' || *s == '*'))
      s++;
    const char *uend = s;
    while (uend < end && *uend != ' ' && *uend != '\t' && *uend != '\r')
      uend++;

    char unit[128];
    size_t ulen = (size_t)(uend - s);
    if (ulen > 0 && ulen < sizeof(unit)) {
      memcpy(unit, s, ulen);
      unit[ulen] = '\0';

      char prop_buf[4096];
      int rc = 0;
      if (is_user) {
        char *const cmd[] = {
            "systemctl",
            "--user",
            "show",
            unit,
            "-p",
            "FragmentPath,ActiveState,SubState,Result,ExecMainStatus,NRestarts,"
            "ExecStart",
            NULL};
        capture_cmd_output(cmd, prop_buf, sizeof(prop_buf), &rc);
      } else {
        char *const cmd[] = {
            "systemctl",
            "show",
            unit,
            "-p",
            "FragmentPath,ActiveState,SubState,Result,ExecMainStatus,NRestarts,"
            "ExecStart",
            NULL};
        capture_cmd_output(cmd, prop_buf, sizeof(prop_buf), &rc);
      }

      char frag[256] = "", active[32] = "", sub[32] = "", result[32] = "";
      char exec_path[256] = "";
      int exit_status = 0, restarts = 0;

      const char *lp = prop_buf;
      while (*lp != '\0') {
        const char *lnl = strchr(lp, '\n');
        size_t n = lnl ? (size_t)(lnl - lp) : strlen(lp);
        if (n > 0 && lp[n - 1] == '\r')
          n--;

        if (n > 13 && strncmp(lp, "FragmentPath=", 13) == 0)
          snprintf(frag, sizeof(frag), "%.*s", (int)(n - 13), lp + 13);
        else if (n > 12 && strncmp(lp, "ActiveState=", 12) == 0)
          snprintf(active, sizeof(active), "%.*s", (int)(n - 12), lp + 12);
        else if (n > 9 && strncmp(lp, "SubState=", 9) == 0)
          snprintf(sub, sizeof(sub), "%.*s", (int)(n - 9), lp + 9);
        else if (n > 7 && strncmp(lp, "Result=", 7) == 0)
          snprintf(result, sizeof(result), "%.*s", (int)(n - 7), lp + 7);
        else if (n > 15 && strncmp(lp, "ExecMainStatus=", 15) == 0)
          exit_status = atoi(lp + 15);
        else if (n > 10 && strncmp(lp, "NRestarts=", 10) == 0)
          restarts = atoi(lp + 10);
        else if (n > 10 && strncmp(lp, "ExecStart=", 10) == 0) {
          const char *path_key = strstr(lp + 10, "path=");
          if (path_key && path_key < lp + n) {
            path_key += 5;
            const char *pe = path_key;
            while (pe < lp + n && *pe != ' ' && *pe != ';')
              pe++;
            snprintf(exec_path, sizeof(exec_path), "%.*s",
                     (int)(pe - path_key), path_key);
          }
        }
        if (!lnl)
          break;
        lp = lnl + 1;
      }

      int exec_missing = (exec_path[0] == '/' && access(exec_path, F_OK) != 0);
      int exec_noexec =
          (!exec_missing && exec_path[0] == '/' && access(exec_path, X_OK) != 0);

      // Pull up to 2 distinct non-boilerplate error lines from journalctl
      char traces[2][256] = {"", ""};
      int trace_count = 0;
      int port_in_use = 0;
      if (have_cmd("journalctl")) {
        char jbuf[4096];
        int jrc = 0;
        if (is_user) {
          char *const jcmd[] = {"journalctl", "--user", "-b",        "-u",
                                unit,         "-n",     "12",        "-o",
                                "cat",        "--no-pager", NULL};
          capture_cmd_output(jcmd, jbuf, sizeof(jbuf), &jrc);
        } else {
          char *const jcmd[] = {"journalctl", "-b", "-u",         unit,
                                "-n",         "12", "-o",         "cat",
                                "--no-pager", NULL};
          capture_cmd_output(jcmd, jbuf, sizeof(jbuf), &jrc);
        }

        const char *jp = jbuf;
        while (*jp != '\0') {
          const char *jnl = strchr(jp, '\n');
          size_t jlen = jnl ? (size_t)(jnl - jp) : strlen(jp);
          if (jlen > 0 && jp[jlen - 1] == '\r')
            jlen--;

          char line[256];
          if (jlen > 0) {
            snprintf(line, sizeof(line), "%.*s", (int)jlen, jp);
            if (strstr(line, "address already in use") ||
                strstr(line, "EADDRINUSE"))
              port_in_use = 1;
            if (!is_systemd_boilerplate_log(line)) {
              int dup = 0;
              for (int t = 0; t < trace_count; t++) {
                if (strcmp(traces[t], line) == 0)
                  dup = 1;
              }
              if (!dup && trace_count < 2)
                snprintf(traces[trace_count++], sizeof(traces[0]), "%s", line);
            }
          }
          if (!jnl)
            break;
          jp = jnl + 1;
        }
      }

      // Check whether a user unit is colliding with an active system unit of
      // the same name (e.g. both user and system ollama.service enabled).
      int sys_twin_active = 0;
      if (is_user) {
        char dummy[64];
        int arc = -1;
        char *const acmd[] = {"systemctl", "is-active", "--quiet", unit, NULL};
        capture_cmd_output(acmd, dummy, sizeof(dummy), &arc);
        if (arc == 0)
          sys_twin_active = 1;
      }

      const char *stag = systemd_exit_tag(exit_status);
      char status_str[32];
      if (stag)
        snprintf(status_str, sizeof(status_str), "%s", stag);
      else
        snprintf(status_str, sizeof(status_str), "%d", exit_status);

      printf("    " CLR_YELLOW "*" CLR_RESET " " CLR_CYAN "%s" CLR_RESET
             " [%s/%s, result=%s, status=%s, restarts=%d]\n",
             unit, active[0] ? active : "?", sub[0] ? sub : "?",
             result[0] ? result : "?", status_str, restarts);
      if (frag[0])
        printf("      Unit : %s\n", frag);
      if (exec_path[0]) {
        if (exec_missing)
          printf("      Exec : %s " CLR_RED "(MISSING on disk!)" CLR_RESET "\n",
                 exec_path);
        else if (exec_noexec)
          printf("      Exec : %s " CLR_RED "(not executable!)" CLR_RESET "\n",
                 exec_path);
        else
          printf("      Exec : %s\n", exec_path);
      }
      for (int t = 0; t < trace_count; t++)
        printf("      Log  : %s\n", traces[t]);

      if (exit_status == 203 || exec_missing) {
        printf("      Why  : Target executable was uninstalled or moved, "
               "leaving an orphaned service.\n");
        printf("      Fix  : systemctl%s disable --now %s\n", scope_flag, unit);
      } else if (exec_noexec) {
        printf("      Why  : Target binary exists but lacks execute "
               "permissions.\n");
        printf("      Fix  : chmod +x %s\n", exec_path);
      } else if (exit_status == 200) {
        printf("      Why  : Configured WorkingDirectory no longer exists on "
               "disk.\n");
        printf("      Fix  : Edit %s or disable with: systemctl%s disable "
               "--now %s\n",
               frag[0] ? frag : unit, scope_flag, unit);
      } else if (sys_twin_active) {
        printf("      Why  : Duplicate unit — system-wide '%s' is already "
               "running%s.\n",
               unit, port_in_use ? " and holding the port" : "");
        printf("      Fix  : systemctl --user disable --now %s\n", unit);
      } else if (port_in_use) {
        printf("      Why  : Port/socket is already bound by another "
               "process.\n");
        printf("      Fix  : ss -tulpn   (or systemctl%s disable --now %s)\n",
               scope_flag, unit);
      } else if (strcmp(result, "core-dump") == 0) {
        printf("      Why  : Service process crashed with a signal/core "
               "dump.\n");
        printf("      Fix  : coredumpctl info %s\n", unit);
      } else {
        printf("      Fix  : journalctl%s -xeu %s\n", scope_flag, unit);
      }
    }

    if (!nl)
      break;
    cur = nl + 1;
  }
}

// Checks both system-wide and per-user systemd managers for failed units AND
// crash-looping (`activating / auto-restart`) units, printing a root-cause
// trace and actionable fix command for each unhealthy service.
void check_systemd_health(void) {
  if (access("/run/systemd/system", F_OK) != 0 || !have_cmd("systemctl"))
    return;

  char *const sys_units[] = {
      "systemctl",  "list-units", "--state=failed,auto-restart",
      "--no-legend", "--plain",   "--no-pager",
      NULL};
  char buf[8192];
  int rc = 0;
  int healthy = 1;

  if (capture_cmd_output(sys_units, buf, sizeof(buf), &rc) > 0 &&
      buf[strspn(buf, " \t\r\n")] != '\0') {
    printf(CLR_YELLOW "[!] Failed or crash-looping system systemd units:\n"
                      CLR_RESET);
    trace_systemd_units(buf, 0);
    healthy = 0;
  }

  const char *xdg = getenv("XDG_RUNTIME_DIR");
  if (xdg && *xdg != '\0') {
    char *const usr_units[] = {"systemctl",
                               "--user",
                               "list-units",
                               "--state=failed,auto-restart",
                               "--no-legend",
                               "--plain",
                               "--no-pager",
                               NULL};
    if (capture_cmd_output(usr_units, buf, sizeof(buf), &rc) > 0 &&
        buf[strspn(buf, " \t\r\n")] != '\0') {
      printf(CLR_YELLOW "[!] Failed or crash-looping user systemd units:\n"
                        CLR_RESET);
      trace_systemd_units(buf, 1);
      healthy = 0;
    }
  }

  if (healthy) {
    printf(CLR_GREEN "[✓] All systemd system & user services healthy.\n"
                     CLR_RESET);
  }
}

static const char *sig_short_name(int sig) {
  switch (sig) {
  case 4:
    return "SIGILL";
  case 5:
    return "SIGTRAP";
  case 6:
    return "SIGABRT";
  case 7:
    return "SIGBUS";
  case 8:
    return "SIGFPE";
  case 11:
    return "SIGSEGV";
  case 31:
    return "SIGSYS";
  default:
    return NULL;
  }
}

// Summarizes any process coredumps recorded during the current boot via
// `coredumpctl --json=short`, deduplicating repeated crashes by executable +
// signal so silent background segfaults/aborts are surfaced cleanly.
void check_boot_coredumps(void) {
  if (access("/run/systemd/system", F_OK) != 0 || !have_cmd("coredumpctl"))
    return;

  struct sysinfo si;
  if (sysinfo(&si) != 0)
    return;
  long long boot_ts = (long long)time(NULL) - (long long)si.uptime;
  if (boot_ts <= 0)
    return;

  char since_arg[64];
  snprintf(since_arg, sizeof(since_arg), "--since=@%lld", boot_ts);

  char buf[32768];
  int rc = -1;
  char *const cmd[] = {"coredumpctl", "list",         since_arg,
                       "--json=short", "--no-pager", NULL};
  if (capture_cmd_output(cmd, buf, sizeof(buf), &rc) <= 0 || rc != 0 ||
      buf[0] != '[') {
    printf(CLR_GREEN "[✓] No process coredumps recorded this boot.\n"
                     CLR_RESET);
    return;
  }

  struct crash_item {
    char exe[256];
    int sig;
    int last_pid;
    size_t count;
  } items[32];
  size_t item_count = 0;

  const char *obj_start = NULL;
  int depth = 0, in_str = 0;
  for (const char *p = buf; *p != '\0'; p++) {
    if (in_str) {
      if (*p == '\\' && *(p + 1) != '\0')
        p++;
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
        char exe[256] = "";
        extract_json_str(obj_start, p, "\"exe\":", exe, sizeof(exe));
        int sig = 0, pid = 0;
        const char *sp = strstr(obj_start, "\"sig\":");
        if (sp && sp < p)
          sig = atoi(sp + 6);
        const char *pp = strstr(obj_start, "\"pid\":");
        if (pp && pp < p)
          pid = atoi(pp + 6);

        if (exe[0] != '\0') {
          size_t idx = item_count;
          for (size_t i = 0; i < item_count; i++) {
            if (strcmp(items[i].exe, exe) == 0 && items[i].sig == sig) {
              idx = i;
              break;
            }
          }
          if (idx < item_count) {
            items[idx].count++;
            if (pid > 0)
              items[idx].last_pid = pid;
          } else if (item_count < 32) {
            snprintf(items[item_count].exe, sizeof(items[0].exe), "%s", exe);
            items[item_count].sig = sig;
            items[item_count].last_pid = pid;
            items[item_count].count = 1;
            item_count++;
          }
        }
        obj_start = NULL;
      }
    }
  }

  if (item_count == 0) {
    printf(CLR_GREEN "[✓] No process coredumps recorded this boot.\n"
                     CLR_RESET);
    return;
  }

  printf(CLR_YELLOW "[!] Process coredumps recorded this boot:\n" CLR_RESET);
  for (size_t i = 0; i < item_count; i++) {
    const char *sname = sig_short_name(items[i].sig);
    char sig_buf[24];
    if (sname)
      snprintf(sig_buf, sizeof(sig_buf), "%s", sname);
    else
      snprintf(sig_buf, sizeof(sig_buf), "SIG#%d", items[i].sig);

    const char *gone =
        (items[i].exe[0] == '/' && access(items[i].exe, F_OK) != 0)
            ? " [binary since removed]"
            : "";

    if (items[i].last_pid > 0) {
      printf("    - %s%s (%s, %zux) -> inspect: coredumpctl info %d\n",
             items[i].exe, gone, sig_buf, items[i].count, items[i].last_pid);
    } else {
      printf("    - %s%s (%s, %zux)\n", items[i].exe, gone, sig_buf,
             items[i].count);
    }
  }
}

// Reports the previous boot's total startup time and its critical dependency
// chain. This is diagnostic only: it does not restart or alter any units.
void check_boot_performance(void) {
  if (access("/run/systemd/system", F_OK) != 0)
    return;
  if (!have_cmd("systemd-analyze")) {
    printf(CLR_MAGENTA "[i] Boot analysis unavailable: systemd-analyze not "
                       "installed.\n" CLR_RESET);
    return;
  }

  printf(CLR_CYAN "\n:: Last boot timing...\n" CLR_RESET);
  char *const time_cmd[] = {"systemd-analyze", "--no-pager", "time", NULL};
  if (run_cmd(time_cmd) != 0) {
    printf(CLR_YELLOW "[!] Could not read systemd boot timing.\n" CLR_RESET);
    return;
  }

  printf(CLR_CYAN "\n:: Last boot critical chain...\n" CLR_RESET);
  char *const chain_cmd[] = {"systemd-analyze", "--no-pager",
                             "critical-chain", NULL};
  if (run_cmd(chain_cmd) != 0)
    printf(CLR_YELLOW "[!] Could not read the systemd critical boot chain.\n"
                      CLR_RESET);
}

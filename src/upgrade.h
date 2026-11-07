#ifndef UPGRADE_H
#define UPGRADE_H

#define _DEFAULT_SOURCE
#include <alpm.h>
#include <alpm_list.h>
#include <ctype.h>
#include <curl/curl.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <pwd.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/prctl.h>
#include <sys/stat.h>
#include <sys/statvfs.h>
#include <sys/sysinfo.h>
#include <sys/types.h>
#include <sys/utsname.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#define UPGRADE_VERSION "3.0.0"

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
  uint8_t in_aur;      // Set to 1 once confirmed present in AUR RPC results
  uint8_t ignored;     // Set to 1 if matched by IgnorePkg/IgnoreGroup
  uint8_t out_of_date; // Set to 1 if OutOfDate is non-null in AUR RPC
  uint8_t orphaned;    // Set to 1 if AUR RPC reports Maintainer: null
};

// Dynamic array of heap-allocated C strings
struct str_vec {
  char **items;
  size_t count;
  size_t cap;
};

// ---- util.c -----------------------------------------------------------------
int run_cmd(char *const argv[]);
ssize_t capture_cmd_output(char *const argv[], char *buf, size_t buf_sz,
                           int *exit_code);
int have_cmd(const char *name);
void print_indented_lines(const char *text);
size_t print_capped_lines(const char *text, size_t max_lines);
void print_step(int *step, int total, const char *msg);

char *conf_value(char *line);
int has_csv_opt(const char *csv, const char *opt);
const char *skip_tokens(const char *s, int n);
int parse_first_int(const char *s, long long *out);
const char *line_after(const char *line, const char *key);
int read_small_file(const char *path, char *buf, size_t sz);
int extract_json_str(const char *start, const char *end, const char *key,
                     char *out, size_t out_sz);

void str_vec_add_unique(struct str_vec *v, const char *s);
int cmp_cstr_ptr(const void *a, const void *b);

size_t write_cb(void *contents, size_t size, size_t nmemb, void *userp);
int acquire_sudo(void);
void stop_sudo_keepalive(void);

// ---- telemetry.c ------------------------------------------------------------
int check_pacman_lock(int check_only);
void check_pacman_keyring(void);
void run_alpm_telemetry(int check_only, int has_aur_helper,
                        int *keyring_needs_update);

// ---- cache.c ----------------------------------------------------------------
void sweep_orphans(const char *aur_helper, int auto_yes);
void clean_pacman_cache(void);
void clean_aur_cache(void);
void clean_systemd_journal(int check_only);

// ---- packages.c -------------------------------------------------------------
void check_package_database(void);
void check_dkms_status(void);
void check_arch_audit(void);
void check_rebuilds(void);
void scan_pacnew_files(void);
void check_shadowed_paths(void);
void pre_upgrade_snapshot(int check_only);
void check_firmware_updates(void);

// ---- systemd_health.c -------------------------------------------------------
void check_systemd_health(void);
void check_boot_coredumps(void);
void check_boot_performance(void);

// ---- hardware.c -------------------------------------------------------------
int check_disk_space(const char *path, double min_gib);
int check_boot_mounts(int check_only);
void check_hardware_health(int check_only);

// ---- sysinfo.c --------------------------------------------------------------
void check_kernel_reboot(void);
void check_stale_libs(void);
void print_sys_summary(void);

#endif // UPGRADE_H

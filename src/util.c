#include "upgrade.h"

// Forks and executes an external command, waiting for it to finish.
// Retries waitpid() if interrupted by a signal (EINTR).
// Returns 0 on exit status 0, -2 if interrupted by SIGINT/SIGTERM, or -1 on
// any other non-zero exit / error.
int run_cmd(char *const argv[]) {
  // Flush our buffered output first so it stays ordered with the child's
  // output when stdout is a pipe or log file (e.g. `upgrade | tee log`)
  fflush(NULL);
  pid_t pid = fork();
  if (pid < 0) {
    perror("fork");
    return -1;
  }
  if (pid == 0) {
    execvp(argv[0], argv);
    perror(argv[0]);
    _exit(127);
  }
  int status;
  while (waitpid(pid, &status, 0) < 0) {
    if (errno != EINTR)
      return -1;
  }
  if (WIFSIGNALED(status) &&
      (WTERMSIG(status) == SIGINT || WTERMSIG(status) == SIGTERM))
    return -2;
  if (WIFEXITED(status)) {
    if (WEXITSTATUS(status) == 0)
      return 0;
    if (WEXITSTATUS(status) == 128 + SIGINT)
      return -2;
  }
  return -1;
}

// Executes `argv`, capturing stdout into `buf` (null-terminated) while routing
// stderr to /dev/null so diagnostic probes stay quiet when optional daemons or
// user buses are unavailable. Returns bytes captured (>= 0), or -1 on error.
ssize_t capture_cmd_output(char *const argv[], char *buf, size_t buf_sz,
                           int *exit_code) {
  if (buf_sz == 0)
    return -1;
  buf[0] = '\0';
  if (exit_code)
    *exit_code = -1;

  int pfd[2];
  if (pipe(pfd) != 0)
    return -1;

  fflush(NULL);
  pid_t pid = fork();
  if (pid < 0) {
    close(pfd[0]);
    close(pfd[1]);
    return -1;
  }
  if (pid == 0) {
    close(pfd[0]);
    dup2(pfd[1], STDOUT_FILENO);
    if (pfd[1] > STDOUT_FILENO)
      close(pfd[1]);
    int devnull = open("/dev/null", O_WRONLY);
    if (devnull >= 0) {
      dup2(devnull, STDERR_FILENO);
      if (devnull > STDERR_FILENO)
        close(devnull);
    }
    execvp(argv[0], argv);
    _exit(127);
  }

  close(pfd[1]);
  size_t total = 0;
  char drain[512];
  for (;;) {
    ssize_t n;
    if (total + 1 < buf_sz)
      n = read(pfd[0], buf + total, buf_sz - 1 - total);
    else
      n = read(pfd[0], drain, sizeof(drain));
    if (n > 0) {
      if (total + 1 < buf_sz)
        total += (size_t)n;
    } else if (n == 0) {
      break;
    } else if (errno != EINTR) {
      break;
    }
  }
  buf[total] = '\0';
  close(pfd[0]);

  int status;
  while (waitpid(pid, &status, 0) < 0) {
    if (errno != EINTR)
      return -1;
  }
  if (exit_code && WIFEXITED(status))
    *exit_code = WEXITSTATUS(status);
  return (ssize_t)total;
}

// Returns 1 if `name` resolves to an executable somewhere in $PATH
int have_cmd(const char *name) {
  const char *path = getenv("PATH");
  if (!path || !*path)
    path = "/usr/local/bin:/usr/bin:/bin";

  char buf[PATH_MAX];
  size_t name_len = strlen(name);
  const char *p = path;
  for (;;) {
    const char *colon = strchr(p, ':');
    size_t len = colon ? (size_t)(colon - p) : strlen(p);
    if (len > 0 && len + 1 + name_len < sizeof(buf)) {
      memcpy(buf, p, len);
      buf[len] = '/';
      memcpy(buf + len + 1, name, name_len + 1);
      if (access(buf, X_OK) == 0)
        return 1;
    }
    if (!colon)
      return 0;
    p = colon + 1;
  }
}

void print_indented_lines(const char *text) {
  const char *p = text;
  while (*p != '\0') {
    const char *nl = strchr(p, '\n');
    size_t len = nl ? (size_t)(nl - p) : strlen(p);
    if (len > 0 && p[len - 1] == '\r')
      len--;
    if (len > 0)
      printf("    %.*s\n", (int)len, p);
    if (!nl)
      break;
    p = nl + 1;
  }
}

// Prints at most `max_lines` non-empty lines of `text`, indented.
size_t print_capped_lines(const char *text, size_t max_lines) {
  size_t total = 0;
  for (const char *p = text; *p != '\0';) {
    const char *nl = strchr(p, '\n');
    size_t len = nl ? (size_t)(nl - p) : strlen(p);
    if (len > 0 && p[len - 1] == '\r')
      len--;
    if (len > 0) {
      if (total < max_lines)
        printf("    %.*s\n", len > 170 ? 170 : (int)len, p);
      total++;
    }
    p = nl ? nl + 1 : p + (len ? len : 1);
  }
  if (total > max_lines)
    printf("    ... and %zu more\n", total - max_lines);
  return total;
}

// Prints a numbered pipeline stage header, e.g. ":: [2/6] Updating ..."
void print_step(int *step, int total, const char *msg) {
  printf(CLR_CYAN "\n:: [%d/%d] %s\n" CLR_RESET, ++*step, total, msg);
}

// Returns the trimmed value of a "Key = Value" config line (modified in
// place), or NULL if the line has no '=' or an empty value.
char *conf_value(char *line) {
  char *v = strchr(line, '=');
  if (!v)
    return NULL;
  v++;
  while (*v == ' ' || *v == '\t')
    v++;
  v[strcspn(v, "\r\n")] = '\0';
  size_t n = strlen(v);
  while (n > 0 && (v[n - 1] == ' ' || v[n - 1] == '\t'))
    v[--n] = '\0';
  return (*v != '\0') ? v : NULL;
}

// Returns 1 if `opt` appears as an exact comma-separated token in `csv`.
int has_csv_opt(const char *csv, const char *opt) {
  size_t olen = strlen(opt);
  const char *p = csv;
  while (*p != '\0') {
    const char *comma = strchr(p, ',');
    size_t len = comma ? (size_t)(comma - p) : strlen(p);
    if (len == olen && strncmp(p, opt, olen) == 0)
      return 1;
    if (!comma)
      break;
    p = comma + 1;
  }
  return 0;
}

// Returns a pointer just past the first `n` whitespace-delimited tokens.
const char *skip_tokens(const char *s, int n) {
  while (n-- > 0) {
    while (*s == ' ' || *s == '\t')
      s++;
    while (*s != '\0' && *s != ' ' && *s != '\t')
      s++;
  }
  return s;
}

// Parses the first run of digits in `s`, ignoring ',' thousands separators.
int parse_first_int(const char *s, long long *out) {
  while (*s != '\0' && !isdigit((unsigned char)*s))
    s++;
  if (*s == '\0')
    return 0;
  long long v = 0;
  while (isdigit((unsigned char)*s) || *s == ',') {
    if (*s != ',') {
      if (v > (LLONG_MAX - 9) / 10)
        break; // saturate instead of overflowing
      v = v * 10 + (*s - '0');
    }
    s++;
  }
  *out = v;
  return 1;
}

// If `line` (after leading blanks) starts with `key`, returns the text after
// it, otherwise NULL.
const char *line_after(const char *line, const char *key) {
  while (*line == ' ' || *line == '\t')
    line++;
  size_t k = strlen(key);
  return strncmp(line, key, k) == 0 ? line + k : NULL;
}

// Reads the first line of a small sysfs/procfs file, trimmed.
int read_small_file(const char *path, char *buf, size_t sz) {
  FILE *fp = fopen(path, "r");
  if (!fp)
    return -1;
  if (!fgets(buf, (int)sz, fp)) {
    fclose(fp);
    return -1;
  }
  fclose(fp);
  buf[strcspn(buf, "\r\n")] = '\0';
  return 0;
}

// Lightweight JSON string extractor for a bounded object slice [start, end).
// Searches for `key` (e.g. "\"Name\":"), skips whitespace, and copies the
// quoted string value into `out` while unescaping backslash sequences.
int extract_json_str(const char *start, const char *end, const char *key,
                     char *out, size_t out_sz) {
  const char *p = start;
  size_t klen = strlen(key);

  while ((p = strstr(p, key)) != NULL && p < end) {
    p += klen;
    while (p < end && (*p == ' ' || *p == '\t'))
      p++;
    if (p < end && *p == '"') {
      p++;
      size_t i = 0;
      while (p < end && *p != '"' && i + 1 < out_sz) {
        if (*p == '\\' && (p + 1) < end)
          p++;
        out[i++] = *p++;
      }
      out[i] = '\0';
      return 0;
    }
  }
  return -1;
}

// Parses a pacman.log timestamp prefix `[YYYY-MM-DDTHH:MM:SS+HHMM]` into UTC
// time_t. Returns 0 on success, -1 on mismatch.
int parse_pacman_log_ts(const char *line, time_t *out) {
  if (!line || line[0] != '[')
    return -1;
  int y, mo, d, H, M, S, tzh, tzm;
  char tzs;
  if (sscanf(line, "[%d-%d-%dT%d:%d:%d%c%2d%2d]", &y, &mo, &d, &H, &M, &S, &tzs,
             &tzh, &tzm) != 9)
    return -1;
  if ((tzs != '+' && tzs != '-') || mo < 1 || mo > 12 || d < 1 || d > 31)
    return -1;
  struct tm tm;
  memset(&tm, 0, sizeof(tm));
  tm.tm_year = y - 1900;
  tm.tm_mon = mo - 1;
  tm.tm_mday = d;
  tm.tm_hour = H;
  tm.tm_min = M;
  tm.tm_sec = S;
  time_t t = timegm(&tm);
  if (t == (time_t)-1)
    return -1;
  long off = (long)tzh * 3600L + (long)tzm * 60L;
  *out = (tzs == '-') ? (t + off) : (t - off);
  return 0;
}

void str_vec_add_unique(struct str_vec *v, const char *s) {
  for (size_t i = 0; i < v->count; i++) {
    if (strcmp(v->items[i], s) == 0)
      return;
  }
  if (v->count == v->cap) {
    size_t ncap = v->cap ? v->cap * 2 : 16;
    char **tmp = realloc(v->items, ncap * sizeof(char *));
    if (!tmp)
      return;
    v->items = tmp;
    v->cap = ncap;
  }
  char *dup = strdup(s);
  if (dup)
    v->items[v->count++] = dup;
}

void str_vec_free(struct str_vec *v) {
  if (!v)
    return;
  for (size_t i = 0; i < v->count; i++)
    free(v->items[i]);
  free(v->items);
  v->items = NULL;
  v->count = 0;
  v->cap = 0;
}

int cmp_cstr_ptr(const void *a, const void *b) {
  return strcmp(*(char *const *)a, *(char *const *)b);
}

// libcurl write callback: appends incoming HTTP response chunks into a
// null-terminated mem_buf on the heap.
size_t write_cb(void *contents, size_t size, size_t nmemb, void *userp) {
  size_t realsize = size * nmemb;
  struct mem_buf *mem = (struct mem_buf *)userp;

  char *ptr = realloc(mem->data, mem->size + realsize + 1);
  if (!ptr)
    return 0;

  mem->data = ptr;
  memcpy(&(mem->data[mem->size]), contents, realsize);
  mem->size += realsize;
  mem->data[mem->size] = '\0';
  return realsize;
}

// PID of the background sudo keep-alive child (-1 when not running)
static pid_t g_sudo_keepalive = -1;

void stop_sudo_keepalive(void) {
  if (g_sudo_keepalive > 0) {
    kill(g_sudo_keepalive, SIGTERM);
    waitpid(g_sudo_keepalive, NULL, 0);
    g_sudo_keepalive = -1;
  }
}

// Obtains sudo rights once for the whole run: reuses a still-valid sudo
// timestamp if there is one, otherwise sudo prompts the user for their
// password a single time. A background child then refreshes the timestamp
// every 60 s, so yay/paru/makepkg, pacman, flatpak, snap and paccache never
// re-prompt mid-run (long AUR builds easily exceed sudo's 5 min default).
// The password is handled entirely by sudo; upgrade never sees or stores it.
int acquire_sudo(void) {
  printf(CLR_CYAN "\n:: Requesting sudo privileges (asked at most once per "
                  "run)...\n" CLR_RESET);
  char *const sudo_validate[] = {"sudo", "-v", NULL};
  if (run_cmd(sudo_validate) != 0)
    return -1;

  pid_t parent = getpid();
  fflush(NULL);
  pid_t pid = fork();
  if (pid < 0)
    return 0; // Non-fatal: sudo may simply re-prompt later
  if (pid == 0) {
    // Die together with upgrade, however it exits (Ctrl+C, crash, ...)
    prctl(PR_SET_PDEATHSIG, SIGTERM);
    if (getppid() != parent)
      _exit(0);

    // Keep quiet: never write into the user's terminal output
    int devnull = open("/dev/null", O_RDWR);
    if (devnull >= 0) {
      dup2(devnull, STDIN_FILENO);
      dup2(devnull, STDOUT_FILENO);
      dup2(devnull, STDERR_FILENO);
      if (devnull > STDERR_FILENO)
        close(devnull);
    }

    char *const sudo_refresh[] = {"sudo", "-n", "-v", NULL};
    for (;;) {
      sleep(60);
      if (getppid() != parent || run_cmd(sudo_refresh) != 0)
        _exit(0);
    }
  }

  g_sudo_keepalive = pid;
  atexit(stop_sudo_keepalive);
  return 0;
}

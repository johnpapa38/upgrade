#include "upgrade.h"
#include <assert.h>

static void test_conf_value(void) {
  char l1[] = "KeepDir = /var/cache/pacman/pkg  \n";
  char *v1 = conf_value(l1);
  assert(v1 != NULL && strcmp(v1, "/var/cache/pacman/pkg") == 0);

  char l2[] = "EmptyVal =   \t\r\n";
  assert(conf_value(l2) == NULL);

  char l3[] = "NoEqualsHere";
  assert(conf_value(l3) == NULL);
}

static void test_csv_and_tokens(void) {
  assert(has_csv_opt("rw,relatime,errors=remount-ro", "rw") == 1);
  assert(has_csv_opt("rw,relatime,errors=remount-ro", "ro") == 0);
  assert(has_csv_opt("ro", "ro") == 1);
  assert(has_csv_opt("rw,ro,noauto", "noauto") == 1);

  const char *s = "  5   Reallocated_Sector_Ct   0x0033   100   100   010";
  const char *p = skip_tokens(s, 3);
  long long val = 0;
  assert(parse_first_int(p, &val) == 1 && val == 100);

  long long num = 0;
  assert(parse_first_int("Data Units Read: 12,345,678 [6.32 TB]", &num) == 1);
  assert(num == 12345678);
  assert(parse_first_int("no digits here", &num) == 0);
}

static void test_json_and_line_helpers(void) {
  const char *la = line_after("    Temperature:   42 Celsius", "Temperature:");
  assert(la != NULL && strstr(la, "42") != NULL);
  assert(line_after("  Temp: 42", "Temperature:") == NULL);

  const char *json =
      "{\"Name\":\"foo-bar\",\"Desc\":\"hello \\\"world\\\"\",\"Version\":\"1:2.0-1\"}";
  char out[64];
  assert(extract_json_str(json, json + strlen(json), "\"Name\":", out,
                          sizeof(out)) == 0);
  assert(strcmp(out, "foo-bar") == 0);

  assert(extract_json_str(json, json + strlen(json), "\"Desc\":", out,
                          sizeof(out)) == 0);
  assert(strcmp(out, "hello \"world\"") == 0);

  assert(extract_json_str(json, json + strlen(json), "\"Missing\":", out,
                          sizeof(out)) == -1);
}

static void test_pacman_log_ts(void) {
  time_t t1 = 0, t2 = 0;
  assert(parse_pacman_log_ts("[2026-11-13T13:21:24+0200] [ALPM] upgraded linux",
                             &t1) == 0);
  assert(parse_pacman_log_ts("[2026-11-13T11:21:24+0000] [ALPM] upgraded linux",
                             &t2) == 0);
  assert(t1 == t2);

  time_t t3 = 0;
  assert(parse_pacman_log_ts("[2026-11-13T06:21:24-0500] [ALPM] upgraded linux",
                             &t3) == 0);
  assert(t3 == t2);

  assert(parse_pacman_log_ts("not a timestamp", &t1) == -1);
  assert(parse_pacman_log_ts("[2026-13-01T00:00:00+0000]", &t1) == -1);
}

static void test_str_vec(void) {
  struct str_vec v = {NULL, 0, 0};
  str_vec_add_unique(&v, "alpha");
  str_vec_add_unique(&v, "beta");
  str_vec_add_unique(&v, "alpha");
  assert(v.count == 2);
  assert(strcmp(v.items[0], "alpha") == 0);
  assert(strcmp(v.items[1], "beta") == 0);
  str_vec_free(&v);
  assert(v.items == NULL && v.count == 0 && v.cap == 0);
}

static void test_tx_delta(void) {
  const char *log_delta =
      "[2026-11-13T13:21:22+0200] [ALPM] upgraded llvm (23.1-1 -> 23.2-1)\n"
      "[2026-11-13T13:21:24+0200] [ALPM] upgraded linux (7.2-1 -> 7.3-1)\n"
      "[2026-11-13T13:21:25+0200] [ALPM] upgraded systemd (258-1 -> 259-1)\n"
      "[2026-11-13T13:21:25+0200] [ALPM] upgraded linux (7.3-1 -> 7.3-2)\n"
      "[2026-11-13T13:21:26+0200] [ALPM] installed libfoo (1.0-1)\n"
      "[2026-11-13T13:21:27+0200] [ALPM] removed oldpkg (0.9-1)\n";

  struct tx_summary tx;
  parse_pacman_log_delta_buf(log_delta, &tx);
  assert(tx.upgraded == 4);
  assert(tx.installed == 1);
  assert(tx.removed == 1);
  assert(strcmp(tx.notable, "linux, systemd") == 0);
}

static void test_parse_checkrebuild_foreign(void) {
  const char *sample = "foreign\textremetuxracer\n"
                       "repo\tsomepkg\n"
                       "foreign     viber  \n"
                       "  foreign\tmkvtoolnix-git\r\n"
                       "foreign\textremetuxracer\n"
                       "other\tignored\n";
  struct str_vec out = {NULL, 0, 0};
  size_t n = parse_checkrebuild_foreign(sample, &out);
  assert(n == 3 && out.count == 3);
  assert(strcmp(out.items[0], "extremetuxracer") == 0);
  assert(strcmp(out.items[1], "viber") == 0);
  assert(strcmp(out.items[2], "mkvtoolnix-git") == 0);
  str_vec_free(&out);

  struct str_vec empty = {NULL, 0, 0};
  assert(parse_checkrebuild_foreign("", &empty) == 0);
  assert(parse_checkrebuild_foreign("repo\tonlyrepo\n", &empty) == 0);
  str_vec_free(&empty);
}

int main(void) {
  test_conf_value();
  test_csv_and_tokens();
  test_json_and_line_helpers();
  test_pacman_log_ts();
  test_str_vec();
  test_tx_delta();
  test_parse_checkrebuild_foreign();
  printf("All upgrade unit tests passed!\n");
  return 0;
}

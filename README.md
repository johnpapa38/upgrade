# upgrade

One command to keep an Arch Linux system fully up to date: official repos, AUR, Flatpak and Snap. It cleans up afterwards and finishes with a health report.

`upgrade` is a small C program built on **libalpm** (the library behind pacman) and **libcurl**. It figures out what your system has and runs only the steps that apply. It works on plain Arch, EndeavourOS, Manjaro-style setups, with or without an AUR helper.

## Features

- **Pre-upgrade report, no root needed**
  - Downloads fresh copies of the sync databases into a private folder you own (`/tmp/upgrade-db-<uid>`). Your system's pacman databases are never touched.
  - Lists pending repo updates and checks every foreign package against the AUR RPC v5 API.
  - Flags foreign packages that are no longer in the AUR.
  - Respects `IgnorePkg` / `IgnoreGroup` from `/etc/pacman.conf`.
- **Asks for sudo once**
  - Uses your existing sudo login if it's still valid, otherwise asks for your password a single time.
  - Keeps the login fresh in the background, so long AUR builds never stop to ask again.
  - The password is handled entirely by `sudo`; `upgrade` never sees or stores it.
- **Upgrades everything**
  - Repo + AUR via `yay` or `paru`, or `sudo pacman -Syu` if neither is installed
  - Flatpak (system and user installations)
  - Snap
- **Cleans up after**
  - Removes orphaned dependencies
  - Trims the pacman cache (keeps the last 2 versions and removes cached packages that are no longer installed)
  - Removes unused Flatpak runtimes
- **Checks system health**
  - Pre-flight checks: free disk space on `/`, the package cache and `/boot`, and whether the pacman database is locked
  - Lists unmerged `.pacnew` / `.pacsave` files
  - Reports failed systemd units
  - Warns if the kernel was upgraded and a reboot is due
  - Lists processes (including root daemons) still running deleted libraries, which should be restarted

## Requirements

| Required | Purpose |
|---|---|
| `pacman` (libalpm), `curl` (libcurl) | Core: already on every Arch system |
| `base-devel` (`gcc`, `make`, `pkgconf`) | Building |
| `sudo` | Running the steps that need root |

| Optional | Enables |
|---|---|
| `yay` or `paru` | AUR upgrades and orphan cleanup through the helper |
| `flatpak` | Flatpak update + unused runtime cleanup |
| `snap` | Snap refresh |
| `pacman-contrib` | `paccache` cache trimming and `pacdiff` |
| `fastfetch` | System summary at the end |

## Build & install

```sh
sudo pacman -S --needed base-devel pacman-contrib
git clone https://github.com/johnpapa38/upgrade.git
cd upgrade
make
sudo make install          # installs to /usr/local/bin/upgrade
```

Uninstall with `sudo make uninstall`. Change the install location with `PREFIX`, e.g. `make install PREFIX=$HOME/.local` (no sudo needed).

## Usage

```sh
upgrade          # full update + cleanup (interactive prompts)
upgrade -y       # unattended: auto-confirm package manager prompts
upgrade -c       # read-only report of pending repo/AUR updates; needs no root
upgrade -h       # help
```

Run it as your **normal user**, not as root and not with `sudo upgrade`. AUR helpers and `makepkg` refuse to build as root. `upgrade` asks for sudo rights itself, only for the steps that need them.

### What a run looks like

```
:: Refreshing sync DBs into /tmp/upgrade-db-1000 (no root needed)...
:: Auditing /var/lib/pacman via libalpm & AUR RPC v5...
[!] Pending Repo Updates (live sync DBs):
    gdu                          5.38.0-1 -> 5.39.0-1
...
:: Requesting sudo privileges (asked at most once per run)...
:: [1/7] Synchronizing & upgrading packages (Repo + AUR)...
:: [2/7] Updating Flatpak apps & runtimes...
:: [3/7] Refreshing Snap packages...
:: [4/7] Sweeping orphaned dependencies...
:: [5/7] Cleaning caches (pacman: keep last 2 versions, drop uninstalled; unused Flatpak runtimes)...
:: [6/7] Scanning for unmerged .pacnew / .pacsave files...
:: [7/7] Checking for degraded systemd services...
[✓] Kernel modules intact (6.x.y-arch1-1) — no immediate reboot required.
[✓] No processes holding stale /usr/lib shared libraries.
```

Steps for tools you don't have installed are skipped automatically.

## Notes

- **`-y` / `--yes`** passes `--noconfirm` to pacman/yay/paru and `-y` to Flatpak. pacman then takes the default answer to every question. For package conflicts that answer is "no", so the upgrade stops instead of guessing. Read the [Arch news](https://archlinux.org/news/) before running unattended upgrades.
- **No signature checks in the report:** the copies of the databases used by `-c` and the pre-upgrade report aren't signature-checked, because root's keyring can't be used without root. They are only used for displaying updates. The real upgrade runs pacman as root with full signature checks.
- **Privacy:** the AUR check sends the names of your foreign (non-repo) packages to `aur.archlinux.org`.
- **Logging:** output stays in the correct order when piped, e.g. `upgrade | tee ~/upgrade.log`.

## License

[MIT](LICENSE)

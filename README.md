# upgrade

One command to keep an Arch Linux system fully up to date: official repos, AUR, Flatpak and Snap. It cleans up afterwards and finishes with a health report.

`upgrade` is a small C program built on **libalpm** (the library behind pacman) and **libcurl**. It figures out what your system has and runs only the steps that apply. It works on plain Arch, EndeavourOS, Manjaro-style setups, with or without an AUR helper.

## Features

- **Pre-upgrade report, no root needed**
  - Downloads fresh copies of the sync databases into a private folder you own (`/tmp/upgrade-db-<uid>`). Your system's pacman databases are never touched.
  - Lists pending repo updates and checks every foreign package against the AUR RPC v5 API, plus previews pending Flatpak and Snap updates in `-c` mode.
  - Audits `/etc/pacman.d/mirrorlist` (active servers, age, unmerged `.pacnew`) and sync DB staleness.
  - Checks the official **Arch Linux News** feed (`archlinux.org/feeds/news/`) and warns if any advisory was posted since your last upgrade.
  - Flags AUR packages marked out-of-date or orphaned (`Maintainer: null`), as well as foreign packages no longer in the AUR.
  - Respects `IgnorePkg` / `IgnoreGroup` from `/etc/pacman.conf`.
- **Asks for sudo once**
  - Uses your existing sudo login if it's still valid, otherwise asks for your password a single time.
  - Keeps the login fresh in the background, so long AUR builds never stop to ask again.
  - The password is handled entirely by `sudo`; `upgrade` never sees or stores it.
- **Upgrades everything smoothly**
  - Clears stale `/var/lib/pacman/db.lck` automatically if its owning process is gone
  - Runs fully unattended once `sudo` is entered (`--noconfirm --ask=4` for pacman/yay/paru, `-y` for Flatpak) and automatically refreshes keys or falls back to repo updates if an AUR build blocks
  - Updates Flatpak (system and user installations) and Snap automatically
- **Cleans up & repairs natively**
  - Rebuilds outdated foreign/AUR packages automatically when `checkrebuild` (`rebuild-detector`) flags broken shared-library links, and automatically removes any broken AUR package that fails to rebuild
  - Removes orphaned dependencies directly via `libalpm`
  - Trims both the pacman cache and `~/.cache/yay` / `~/.cache/paru/clone` built `.pkg.tar*` archives (keeps the last 2 versions of installed packages, drops cached tarballs for uninstalled packages, sweeps leftover `download-*` sandbox folders, and leaves `PKGBUILD`s / git clones untouched)
  - Audits and vacuums `/var/log/journal` when it exceeds `500 MiB`
  - Removes unused Flatpak runtimes
- **Pre-upgrade snapshots & package consistency**
  - Creates a rollback snapshot before package transactions via `snapper` or `timeshift` (or integrates automatically with `snap-pac` ALPM hooks)
  - Upgradable vulnerability and CVE audit via `arch-audit` (when installed)
  - Boot & initramfs/UKI integrity audit (`check_boot_integrity`: verifies `/usr/lib/modules/*/modules.dep.bin` and initramfs/UKI images before rebooting)
- **Checks system health & prints a built-in summary**
  - Pre-flight checks: free disk space on `/`, the package cache, and `/boot` / `/efi` / `/boot/efi`, `/etc/fstab` boot/ESP mount status, and whether pacman is locked
  - Local package database consistency (`pacman -Dkq`) and DKMS kernel module audit (`dkms status`)
  - Scans `.pacnew` / `.pacsave` / `.pacorig` files via `libalpm` backup metadata + `/etc` walk
  - Audits unmanaged binaries in `/usr/local/bin` or `~/.local/bin` shadowing `/usr/bin`, custom `/etc/systemd/system/*.service` masking package units, and dangling `.wants` symlinks
  - Checks system-wide and `--user` systemd managers for failed/crash-looping services with root-cause traces, current-boot coredumps, and concise boot timing
  - Hardware health audit: SMART disk health (`smartctl`), EDAC RAM ECC, DMI DIMM capacity vs usable RAM (`dmidecode`), CPU & GPU thermals (`hwmon` / `nvidia-smi`), Btrfs `device stats` & `fstrim.timer`, and storage/filesystem/MCE/OOM kernel errors (`journalctl -k`)
  - Built-in C system summary card, kernel/core-package reboot advice, running apps still holding older binaries/libraries, and transaction summary

## Requirements

| Required | Purpose |
|---|---|
| `pacman` (libalpm), `curl` (libcurl) | Core: already on every Arch system |
| `base-devel` (`gcc`, `make`, `pkgconf`) | Building |
| `sudo` | Running the steps that need root |

| Optional | Enables |
|---|---|
| `yay` or `paru` | AUR upgrades |
| `flatpak` | Flatpak update + unused runtime cleanup |
| `snap` | Snap refresh |
| `smartmontools` (`smartctl`) | NVMe / SATA SMART disk health & wear check |
| `dmidecode` | Installed DIMM capacity vs usable RAM check |
| `arch-audit` | Upgradable CVE vulnerability audit |
| `rebuild-detector` (`checkrebuild`) | Foreign/AUR library rebuild check |
| `snapper`, `snap-pac`, or `timeshift` | Pre-upgrade rollback snapshots |
| `fwupd` (`fwupdmgr`) | LVFS device firmware update check |

## Build & install

```sh
sudo pacman -S --needed base-devel
git clone https://github.com/johnpapa38/upgrade.git
cd upgrade
make
sudo make install          # installs /usr/local/bin/upgrade and 'up' symlink
```

Uninstall with `sudo make uninstall`. Change the install location with `PREFIX`, e.g. `make install PREFIX=$HOME/.local` (no sudo needed).

## Usage

```sh
up                  # (or `upgrade`) update everything, clean caches, check health
up -c               # read-only preview of updates and system health
up -v               # show version
up -h               # show help
```

Run `make test` to execute the sanitizer-enabled unit tests.

Run it as your **normal user**, not as root and not with `sudo upgrade`. AUR helpers and `makepkg` refuse to build as root. `up` asks for `sudo` once and keeps it alive for the steps that need it.

### What a run looks like

```
[✓] Arch Linux News: no new advisories since last upgrade.

[✓] Storage check '/': 426.30 GiB available.
[✓] Storage check '/var/cache/pacman/pkg': 426.30 GiB available.
[✓] Storage check '/efi': 1.80 GiB available.

:: Requesting sudo privileges (asked at most once per run)...
:: [1/8] Synchronizing & upgrading packages (Repo + AUR)...
:: [2/8] Updating Flatpak apps & runtimes...
:: [3/8] Refreshing Snap packages...
:: [4/8] Verifying package database & rebuilds...
:: [5/8] Sweeping orphaned dependencies...
:: [6/8] Cleaning caches (pacman/AUR, journal & Flatpak)...
:: [7/8] Scanning for unmerged .pacnew / .pacsave & shadowed paths...
:: [8/8] Checking system, hardware, boot & running apps...

   user@arch
   ---------
   OS         Arch Linux (x86_64)
   Kernel     6.x.y-arch1-1
   Uptime     5h 12m (load 0.42, 0.38)
   CPU        AMD Ryzen ... (16 threads)
   Memory     4.10 / 31.20 GiB (13%)
   Disk (/)   48.20 / 500.00 GiB used (426.30 GiB free)
   Packages   1120 (pacman, 18.40 GiB), 14 (flatpak)

[✓] Kernel modules intact (6.x.y-arch1-1) — no immediate reboot required.
[✓] All running apps are up to date.
```

Steps for tools you don't have installed are skipped silently.

## Notes

- **100% automatic once `sudo` is entered:** `up` passes `--noconfirm --ask=4` (`ALPM_QUESTION_CONFLICT_PKG`) to pacman/yay/paru and `-y` to Flatpak so replacements happen automatically without prompting. If an update fails due to keys or a flaky AUR build, `up` refreshes `archlinux-keyring` and falls back to upgrading official packages cleanly; broken AUR packages that fail `checkrebuild` are automatically removed. Read the [Arch news](https://archlinux.org/news/) (checked automatically before upgrading) if an advisory appears.
- **No signature checks in the report:** the copies of the databases used by `-c` and the pre-upgrade report aren't signature-checked, because root's keyring can't be used without root. They are only used for displaying updates. The real upgrade runs pacman as root with full signature checks.
- **Privacy:** the AUR check sends the names of your foreign (non-repo) packages to `aur.archlinux.org`.
- **Logging:** output stays in the correct order when piped, e.g. `upgrade | tee ~/upgrade.log`.

## License

[MIT](LICENSE)

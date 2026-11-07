# upgrade

One command to keep an Arch Linux system fully up to date: official repos, AUR, Flatpak and Snap. It cleans up afterwards and finishes with a health report.

`upgrade` is a small C program built on **libalpm** (the library behind pacman) and **libcurl**. It figures out what your system has and runs only the steps that apply. It works on plain Arch, EndeavourOS, Manjaro-style setups, with or without an AUR helper.

## Features

- **Pre-upgrade report, no root needed**
  - Downloads fresh copies of the sync databases into a private folder you own (`/tmp/upgrade-db-<uid>`). Your system's pacman databases are never touched.
  - Lists pending repo updates and checks every foreign package against the AUR RPC v5 API.
  - Checks the official **Arch Linux News** feed (`archlinux.org/feeds/news/`) and warns if any advisory was posted since your last upgrade.
  - Flags AUR packages marked out-of-date or orphaned (`Maintainer: null`), as well as foreign packages no longer in the AUR.
  - Respects `IgnorePkg` / `IgnoreGroup` from `/etc/pacman.conf`.
- **Asks for sudo once**
  - Uses your existing sudo login if it's still valid, otherwise asks for your password a single time.
  - Keeps the login fresh in the background, so long AUR builds never stop to ask again.
  - The password is handled entirely by `sudo`; `upgrade` never sees or stores it.
- **Upgrades everything**
  - Repo + AUR via `yay` or `paru`, or `sudo pacman -Syu` if neither is installed
  - Flatpak (system and user installations)
  - Snap
- **Cleans up natively (no `pacman-contrib` needed)**
  - Detects orphaned dependencies directly via `libalpm` (skips cleanup altogether when 0 orphans exist)
  - Trims both the pacman cache and `~/.cache/yay` / `~/.cache/paru/clone` built `.pkg.tar*` archives in C using `alpm_pkg_vercmp()` (keeps the last 2 versions of installed packages, drops cached tarballs for uninstalled packages, sweeps leftover `download-*` sandbox folders, and leaves `PKGBUILD`s / git clones untouched)
  - Removes unused Flatpak runtimes
- **Pre-upgrade snapshots & package consistency**
  - Creates a rollback snapshot before package transactions via `snapper` or `timeshift` (or integrates automatically with `snap-pac` ALPM hooks)
  - Rebuild detection for foreign/AUR packages linked against upgraded libraries (`checkrebuild` / `rebuild-detector`)
  - Upgradable vulnerability and CVE audit via `arch-audit`
- **Checks system health & prints a built-in C summary (no `fastfetch` needed)**
  - Pre-flight checks: free disk space on `/`, the package cache, and `/boot` / `/efi` / `/boot/efi`, whether any `/etc/fstab` boot/ESP partition is unmounted or read-only (`ro`), and whether the pacman database is locked
  - Local package database consistency verification (`pacman -Dkq`) and DKMS kernel module build audit (`dkms status`, when installed)
  - Native `.pacnew` / `.pacsave` / `.pacorig` scanner via `libalpm` backup metadata + `/etc` walk
  - Configuration-drift & shadowing audit: flags unmanaged binaries in `/usr/local/bin` or `~/.local/bin` that shadow `/usr/bin` packages, custom `/etc/systemd/system/*.service` copies masking package units, and dangling `.wants` symlinks
  - Checks both system-wide and `--user` systemd managers for failed and crash-looping (`auto-restart`) services — printing a root-cause trace (`Unit`, `Exec`, filtered `journalctl` error log, plain-English `Why`, and exact `Fix` command) instead of bare unit names — plus current-boot coredump summary (`coredumpctl`) and boot timing (`systemd-analyze`)
  - Deep hardware health audit: SMART telemetry & wear/temperature for internal NVMe/SATA disks (`smartctl`), EDAC RAM ECC errors, DMI DIMM inventory vs kernel usable memory (`dmidecode`), and storage I/O, filesystem corruption, MCE, or OOM events from the kernel log (`journalctl -k`)
  - Built-in C system summary card (OS, kernel, uptime + load, CPU, RAM, `/` disk, package counts)
  - Warns if the kernel was upgraded and a reboot is due
  - Lists processes (including root daemons) running a deleted executable or holding deleted shared libraries in RAM

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
up               # (or `upgrade`) full update + cleanup (interactive prompts)
up -y            # unattended: auto-confirm prompts + conflict replacements
up -c            # read-only update, package DB, DKMS, service, boot & hardware report
up --hw          # quick standalone hardware health (SMART, RAM, thermals, kernel) & summary
up -v            # version
up -h            # help
```

Run it as your **normal user**, not as root and not with `sudo upgrade`. AUR helpers and `makepkg` refuse to build as root. `upgrade` asks for sudo rights itself, only for the steps that need them.

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
:: [4/8] Verifying package database consistency...
:: [5/8] Sweeping orphaned dependencies...
:: [6/8] Cleaning caches (pacman/AUR: keep last 2 versions, drop uninstalled; unused Flatpak runtimes)...
:: [7/8] Scanning for unmerged .pacnew / .pacsave & shadowed paths...
:: [8/8] Checking systemd system & user service health...

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
[✓] No processes holding stale binaries or shared libraries.
```

Steps for tools you don't have installed are skipped automatically.

## Notes

- **`-y` / `--yes` & package conflicts:** passes `--noconfirm --ask=4` (`ALPM_QUESTION_CONFLICT_PKG`) to pacman/yay/paru and `-y` to Flatpak, so legitimate repo package replacements swap atomically inside the transaction without blindly removing dependency trees. If `-y` still hits an unresolvable dependency conflict while running in a terminal, `upgrade` automatically retries `-Syu` interactively so you can inspect and decide. Read the [Arch news](https://archlinux.org/news/) (also checked automatically before upgrading) for manual-intervention notices.
- **No signature checks in the report:** the copies of the databases used by `-c` and the pre-upgrade report aren't signature-checked, because root's keyring can't be used without root. They are only used for displaying updates. The real upgrade runs pacman as root with full signature checks.
- **Privacy:** the AUR check sends the names of your foreign (non-repo) packages to `aur.archlinux.org`.
- **Logging:** output stays in the correct order when piped, e.g. `upgrade | tee ~/upgrade.log`.

## License

[MIT](LICENSE)

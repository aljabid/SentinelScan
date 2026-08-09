# Installation Guide

## Requirements

- Python 3.9 or higher
- pip

## Install from Source

```bash
git clone https://github.com/aljabid/SentinelScan.git
cd sentinelscan
pip install -e .
```

## Install with DNS Support

DNS checks (SPF, DMARC) require `dnspython`:

```bash
pip install -e ".[dns]"
```

## Install for Development

```bash
pip install -e ".[dev]"
```

This installs: `pytest`, `pytest-cov`, `black`, `ruff`.

## Verify Installation

```bash
sentinelscan --version
# SentinelScan 2.0.0
```

## Windows Notes

Ensure Python Scripts directory is in your PATH:

```powershell
# Add to PATH if sentinelscan command is not found
$env:PATH += ";$env:APPDATA\Python\Python313\Scripts"
# Or for system Python:
$env:PATH += ";C:\Users\<you>\AppData\Local\Programs\Python\Python313\Scripts"
```

## Upgrading from v1.0.0

Simply reinstall:

```bash
pip install -e . --upgrade
```

All new modules (cookies, cors, dns, ports) are enabled by default when using `-m all`.

## Package Manager Installs (planned)

Package definitions for Debian/Ubuntu (`.deb`), Fedora/RHEL/openSUSE (`.rpm`),
Arch/BlackArch (AUR), and Homebrew exist under [`packaging/`](packaging/) and
the root [`debian/`](debian/) directory, but nothing is published to a real
package repository yet (they reference a placeholder GitHub URL). Once a
tagged release exists, see [RELEASING.md](RELEASING.md) for the publish
process — after which installs will look like:

```bash
# Debian/Ubuntu, once a PPA exists
sudo apt install sentinelscan

# Arch/BlackArch, once published to the AUR
yay -S sentinelscan

# macOS/Linuxbrew, once a tap exists
brew install sentinelscan
```

## Shell Completions & Man Page

Already available from source, without waiting on package manager installs:

```bash
man man/sentinelscan.1                                    # or: man -l man/sentinelscan.1
source completions/sentinelscan.bash                       # bash, current session
cp completions/_sentinelscan /usr/share/zsh/site-functions/ # zsh
cp completions/sentinelscan.fish ~/.config/fish/completions/
```

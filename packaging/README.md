# Packaging

Distribution package definitions for SentinelScan. Debian packaging lives at
the repo root (`../debian/`, the standard location `dpkg-buildpackage`
expects); everything else is namespaced here by target.

| Path | Target | Status |
|------|--------|--------|
| `../debian/` | Debian/Ubuntu `.deb`, and the basis for a PPA | **Built and verified locally**: `dpkg-buildpackage -us -uc -b` produces a package that passes `lintian --pedantic` with zero errors/warnings, installs correctly (single version-independent copy, no bundled test suite, correctly-named completions), and the real installed binary was exercised (`--version`, `--doctor`, a live scan) |
| `rpm/sentinelscan.spec` | Fedora/RHEL/openSUSE | Written to spec; **not build-tested** (no `rpmbuild` available here) |
| `aur/PKGBUILD` | Arch/Manjaro/BlackArch | Written to spec; **not build-tested** (no `makepkg` available here); ships with `sha256sums=('SKIP')` — run `updpkgsums` against the real release tarball before submitting |
| `homebrew/sentinelscan.rb` | macOS/Linuxbrew | Written to spec; dependency (`requests`/`urllib3`) hashes are real (fetched from PyPI); the formula's own tarball hash is a placeholder until a real tagged release exists |
| `snap/snapcraft.yaml` | Universal (snapd) | Written to spec; **not build-tested** (no `snapcraft` available here) |

None of these (including the verified `debian/` build) can be submitted
anywhere real until the project has a real public repository URL and a
tagged release — every file here currently points at a placeholder
`github.com/aljabid/SentinelScan` URL. Update that URL project-wide
before using any of these for a real submission.

Two real packaging bugs were found and fixed while verifying the Debian
build (both applied project-wide, not just to `debian/`):
1. `setup.py`'s `find_packages()` was installing the `tests/` directory as
   an importable top-level `tests` package — an overly generic name that
   could collide with other installed packages' own `tests` module. Fixed
   with `find_packages(exclude=["tests", "tests.*"])`.
2. `setup.py`'s `data_files` (for the man page/completions) produced
   duplicate, inconsistently-named installs when combined with distro
   packaging's own explicit installs (e.g. `dh_install`'s bare `.install`
   file mappings don't rename files the way `install -Dm644` does — it
   nests the source into a wrongly-named directory instead). Removed
   `data_files` entirely; every packaging format now installs these assets
   itself, explicitly and correctly-named.

See [`../RELEASING.md`](../RELEASING.md) for the full release process,
including which steps are automated by CI and which need a maintainer's own
credentials (GPG key, PyPI token, AUR SSH key, Launchpad account).

# Releasing SentinelScan

This describes the full release process: what `.github/workflows/release.yml`
automates, and the manual steps that need credentials only a maintainer
should hold (GPG key, PyPI token, AUR SSH key, Launchpad account).

## 1. Before tagging

- [ ] Update `__version__` in `sentinelscan/__init__.py`
- [ ] Update `version` in `setup.py`
- [ ] Update `pkgver` in `packaging/aur/PKGBUILD`
- [ ] Update `Version`/`Release` in `packaging/rpm/sentinelscan.spec`, add a `%changelog` entry
- [ ] Update `version` in `packaging/homebrew/sentinelscan.rb` and `packaging/snap/snapcraft.yaml`
- [ ] Add a `debian/changelog` entry: `dch -v <version>-1 "Release notes"`
- [ ] Move `[Unreleased]` in `CHANGELOG.md` to a new dated version heading
- [ ] Run the full local check: `pytest tests/ -v && ruff check . && black --check . && mypy sentinelscan/`

## 2. Tag and push

```bash
git tag -a v2.1.0 -m "v2.1.0"
git push origin v2.1.0
```

This triggers `.github/workflows/release.yml`, which:

1. Re-runs the full test/lint/type-check suite as a release gate
2. Builds the sdist + wheel (`python -m build`)
3. Builds a `.deb` and runs `lintian` on it
4. Creates a **draft** GitHub Release with those artifacts attached

**Nothing is published automatically.** A maintainer must review the draft
release and explicitly publish it, then complete the steps below.

## 3. Manual steps requiring your credentials

### GPG-sign release artifacts

```bash
gpg --detach-sign --armor dist/sentinelscan-2.1.0.tar.gz
gpg --detach-sign --armor dist/sentinelscan-2.1.0-py3-none-any.whl
```

Attach the resulting `.asc` files to the GitHub release before publishing it.
Requires a GPG key you control — generate one with `gpg --full-generate-key`
if you don't have one yet, and publish the public key (e.g. to
`keys.openpgp.org`) so users can verify signatures.

### Publish to PyPI

```bash
pip install twine
twine upload dist/sentinelscan-2.1.0*
```

Requires a PyPI account and API token (`~/.pypirc` or `TWINE_PASSWORD` env var).

### Push to AUR

Requires an AUR account with an SSH key registered.

```bash
git clone ssh://aur@aur.archlinux.org/sentinelscan.git aur-sentinelscan
cp packaging/aur/PKGBUILD aur-sentinelscan/
cd aur-sentinelscan
updpkgsums          # computes real sha256sums (PKGBUILD ships with sha256sums=('SKIP'))
makepkg --printsrcinfo > .SRCINFO
git add PKGBUILD .SRCINFO
git commit -m "Update to 2.1.0"
git push
```

### Publish the Ubuntu PPA

Requires a Launchpad account with a signed GPG key uploaded to it.

```bash
debuild -S -sa                      # build a signed source package
dput ppa:aljabid/SentinelScan ../sentinelscan_2.1.0-1_source.changes
```

### Update the Homebrew formula

Requires `sha256 REPLACE_WITH_REAL_TARBALL_SHA256` in
`packaging/homebrew/sentinelscan.rb` to be replaced with the real hash of the
tagged release tarball:

```bash
curl -sL https://github.com/aljabid/SentinelScan/archive/refs/tags/v2.1.0.tar.gz | shasum -a 256
```

Then open a PR against your Homebrew tap (or `homebrew-core`, if the project
qualifies — see Homebrew's acceptance criteria).

### Submit to Fedora / COPR

`packaging/rpm/sentinelscan.spec` has never been build-tested locally (no
`rpmbuild` available in this environment). Before submitting:

```bash
rpmbuild -ba packaging/rpm/sentinelscan.spec   # on a Fedora/RHEL box, or via mock/COPR
rpmlint <resulting .rpm>
```

### Kali Linux inclusion

The highest-credibility target for a pentest tool, and the slowest: Kali
requires the tool to be genuinely useful, actively maintained, properly
licensed, and packaged to Debian standards (which `debian/` here follows).
Submit via their tool-addition process (their tracker, not a PR) once the
project has real public releases and some track record. This is a
maintainer-driven, months-scale process — not something to automate.

### Debian archive inclusion

The slow, formal path to being in every default Debian/Ubuntu install: file
an ITP (Intent To Package) bug, find a Debian Developer sponsor, and pass
Debian Policy review. The PPA (above) is the fast path that gets you a real
`apt install` today; archive inclusion is a longer-term goal on top of that.

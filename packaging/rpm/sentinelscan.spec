Name:           sentinelscan
Version:        2.0.0
Release:        1%{?dist}
Summary:        Web Security Scanner, modular

License:        MIT
URL:            https://github.com/aljabid/SentinelScan
Source0:        %{url}/archive/refs/tags/v%{version}.tar.gz#/%{name}-%{version}.tar.gz

BuildArch:      noarch
BuildRequires:  python3-devel
BuildRequires:  python3-setuptools
BuildRequires:  python3-pip

Requires:       python3-requests >= 2.28.0
Requires:       python3-urllib3 >= 1.26.0
Recommends:     python3-dns

%description
SentinelScan is a modular web security scanner covering HTTP header
misconfigurations, TLS/SSL issues, cookie flaws, CORS vulnerabilities,
DNS email-security gaps, exposed ports (with banner grabbing), passive
subdomain enumeration, multi-page header-consistency crawling, and
known-vulnerable software version fingerprinting. It supports an
external plugin system, CI/CD exit-code gating, timing templates, and
text/JSON/HTML/SARIF report output.

%prep
%autosetup -n %{name}-%{version}

%build
%py3_build

%install
%py3_install
install -Dm644 man/sentinelscan.1 %{buildroot}%{_mandir}/man1/sentinelscan.1
install -Dm644 completions/sentinelscan.bash %{buildroot}%{_datadir}/bash-completion/completions/sentinelscan
install -Dm644 completions/_sentinelscan %{buildroot}%{_datadir}/zsh/site-functions/_sentinelscan
install -Dm644 completions/sentinelscan.fish %{buildroot}%{_datadir}/fish/vendor_completions.d/sentinelscan.fish

%files
%license LICENSE
%doc README.md CHANGELOG.md USAGE.md CONFIG.md
%{python3_sitelib}/sentinelscan/
%{python3_sitelib}/sentinelscan-%{version}*.egg-info/
%{_bindir}/sentinelscan
%{_mandir}/man1/sentinelscan.1*
%{_datadir}/bash-completion/completions/sentinelscan
%{_datadir}/zsh/site-functions/_sentinelscan
%{_datadir}/fish/vendor_completions.d/sentinelscan.fish

%changelog
* Mon Aug 04 2026 SentinelScan Contributors <noreply@example.com> - 2.0.0-1
- Initial RPM packaging: concurrent scanning engine, 4 new modules
  (subdomains, crawler, cve_fingerprint, plugin system), SARIF output,
  authenticated scanning, config profiles, man page, shell completions.

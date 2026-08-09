class Sentinelscan < Formula
  include Language::Python::Virtualenv

  desc "Web Security Scanner, modular"
  homepage "https://github.com/aljabid/SentinelScan"
  url "https://github.com/aljabid/SentinelScan/archive/refs/tags/v2.0.0.tar.gz"
  # TODO: replace with `shasum -a 256` of the real release tarball once tagged and published.
  sha256 "REPLACE_WITH_REAL_TARBALL_SHA256"
  license "MIT"

  depends_on "python@3.12"

  resource "requests" do
    url "https://files.pythonhosted.org/packages/9d/be/10918a2eac4ae9f02f6cfe6414b7a155ccd8f7f9d4380d62fd5b955065c3/requests-2.31.0.tar.gz"
    sha256 "942c5a758f98d790eaed1a29cb6eefc7ffb0d1cf7af05c3d2791656dbd6ad1e1"
  end

  resource "urllib3" do
    url "https://files.pythonhosted.org/packages/36/dd/a6b232f449e1bc71802a5b7950dc3675d32c6dbc2a1bd6d71f065551adb6/urllib3-2.1.0.tar.gz"
    sha256 "df7aa8afb0148fa78488e7899b2c59b5f4ffcfa82e6c54ccb9dd37c1d7b52d54"
  end

  def install
    virtualenv_install_with_resources
    man1.install "man/sentinelscan.1"
    bash_completion.install "completions/sentinelscan.bash" => "sentinelscan"
    zsh_completion.install "completions/_sentinelscan"
    fish_completion.install "completions/sentinelscan.fish"
  end

  test do
    assert_match "SentinelScan 2.0.0", shell_output("#{bin}/sentinelscan --version")
    assert_match "usage: sentinelscan", shell_output("#{bin}/sentinelscan --help")
  end
end

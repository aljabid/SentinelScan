"""Setup configuration for SentinelScan."""

from setuptools import setup, find_packages
import pathlib

HERE = pathlib.Path(__file__).parent
README = (HERE / "README.md").read_text(encoding="utf-8") if (HERE / "README.md").exists() else ""

setup(
    name="sentinelscan",
    version="2.0.0",
    description="Web Security Scanner, modular",
    long_description=README,
    long_description_content_type="text/markdown",
    author="SentinelScan",
    python_requires=">=3.9",
    packages=find_packages(exclude=["tests", "tests.*"]),
    package_data={"sentinelscan": ["data/*.json"]},
    include_package_data=True,
    # No data_files: each distro package (debian/, packaging/rpm, packaging/aur,
    # packaging/homebrew) installs the man page and shell completions explicitly
    # and correctly-named itself. setup.py's data_files handling is inconsistent
    # across pip/wheel/dh_install and caused duplicate, wrongly-named installs.
    install_requires=[
        "requests>=2.28.0",
        "urllib3>=1.26.0",
        "tomli>=2.0; python_version < '3.11'",
    ],
    extras_require={
        "dns": ["dnspython>=2.3.0"],
        "dev": [
            "pytest>=7.0",
            "pytest-cov>=4.0",
            "black>=23.0",
            "ruff>=0.1.0",
            "mypy>=1.8",
            "types-requests",
            # Unconditional (unlike the runtime dep) so mypy can resolve the tomllib/tomli
            # fallback import in sentinelscan/config_file.py regardless of which Python
            # version is running the lint job.
            "tomli>=2.0",
        ],
    },
    entry_points={
        "console_scripts": [
            "sentinelscan=sentinelscan.cli:main",
        ],
    },
    classifiers=[
        "Development Status :: 4 - Beta",
        "Environment :: Console",
        "Intended Audience :: Information Technology",
        "Intended Audience :: Developers",
        "Topic :: Security",
        "Topic :: Internet :: WWW/HTTP",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Programming Language :: Python :: 3.12",
        "Programming Language :: Python :: 3.13",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
    ],
    keywords="security scanner web headers ssl tls owasp cors dns penetration-testing",
)

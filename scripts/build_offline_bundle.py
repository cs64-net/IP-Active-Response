#!/usr/bin/env python3
"""Build the OpenCanary offline installation bundle.

This script packages the OpenCanary source tree, pre-downloaded Python wheel
dependencies, the install shell script, and the systemd service unit into a
single gzip-compressed tar archive suitable for air-gapped deployment.

Usage:
    python scripts/build_offline_bundle.py [--source-dir DIR] [--output PATH]
                                           [--python-version VER] [--platform PLAT]
"""

from typing import List, Optional

import argparse
import glob
import logging
import os
import shutil
import subprocess
import tarfile
import tempfile

logger = logging.getLogger(__name__)

# All direct dependencies from opencanary/opencanary-master/setup.py
REQUIRED_PACKAGES = [
    "Twisted",
    "pyasn1",
    "cryptography",
    "simplejson",
    "requests",
    "zope.interface",
    "PyPDF2",
    "fpdf",
    "passlib",
    "Jinja2",
    "ntlmlib",
    "bcrypt",
    "setuptools<81",
    "urllib3",
    "hpfeeds",
    "pyOpenSSL",
    "service-identity",
]

# Packages that are pure-Python and may not have binary wheels available.
# These need --no-binary to allow downloading source distributions.
PURE_PYTHON_PACKAGES = {
    "fpdf",
    "ntlmlib",
    "hpfeeds",
    "PyPDF2",
    "passlib",
    "pyasn1",
    "service-identity",
}

# Packages with C extensions that must be downloaded as binary wheels.
BINARY_PACKAGES = [p for p in REQUIRED_PACKAGES if p not in PURE_PYTHON_PACKAGES]
SOURCE_PACKAGES = [p for p in REQUIRED_PACKAGES if p in PURE_PYTHON_PACKAGES]


# System .deb packages needed on the target that may not be present on a
# default Ubuntu/Debian minimal install.  We download these during bundle
# build so the installer can dpkg -i them on air-gapped hosts.
# We include version-specific python3.X-venv packages for common versions.
REQUIRED_DEB_PACKAGES = [
    "python3-venv",
    "python3.10-venv",
    "python3.11-venv",
    "python3.12-venv",
]

# URL for get-pip.py — used as a fallback to bootstrap pip without
# requiring python3-venv on the target system.
GET_PIP_URL = "https://bootstrap.pypa.io/get-pip.py"


def _download_debs(dest_dir: str) -> None:
    """Download .deb packages into *dest_dir*.

    Uses ``apt-get download`` which is available in the Debian-based Docker
    build image.  Downloads each package individually so that missing packages
    (e.g. python3.10-venv on a Bookworm host) don't block the others.
    """
    os.makedirs(dest_dir, exist_ok=True)

    # Make sure the apt cache is up-to-date
    subprocess.run(["apt-get", "update", "-qq"], check=False,
                   stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

    downloaded = 0
    for pkg in REQUIRED_DEB_PACKAGES:
        result = subprocess.run(
            ["apt-get", "download", pkg], cwd=dest_dir,
            check=False, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        )
        if result.returncode == 0:
            downloaded += 1
            logger.info("Downloaded deb: %s", pkg)
        else:
            logger.info("Skipped deb (not available in this repo): %s", pkg)

    deb_files = glob.glob(os.path.join(dest_dir, "*.deb"))
    logger.info("Downloaded %d .deb files into bundle", len(deb_files))


def _download_get_pip(dest_dir: str) -> None:
    """Download get-pip.py into *dest_dir* for bootstrapping pip without venv."""
    os.makedirs(dest_dir, exist_ok=True)
    dest = os.path.join(dest_dir, "get-pip.py")

    # Method 1: Use Python's urllib (always available in the Docker image)
    try:
        import urllib.request
        logger.info("Downloading get-pip.py via urllib...")
        urllib.request.urlretrieve(GET_PIP_URL, dest)
        if os.path.isfile(dest) and os.path.getsize(dest) > 1000:
            logger.info("Downloaded get-pip.py (%d bytes)", os.path.getsize(dest))
            return
    except Exception as exc:
        logger.warning("urllib download failed: %s", exc)

    # Method 2: Try curl/wget as fallback
    for cmd in [["curl", "-sfL", "-o", dest, GET_PIP_URL],
                ["wget", "-q", "-O", dest, GET_PIP_URL]]:
        try:
            subprocess.run(cmd, check=True, stdout=subprocess.PIPE,
                           stderr=subprocess.PIPE)
            logger.info("Downloaded get-pip.py")
            return
        except (subprocess.CalledProcessError, FileNotFoundError):
            continue
    logger.warning("Could not download get-pip.py — venv fallback won't work")


def build_offline_bundle(
    source_dir: str = "opencanary/opencanary-master",
    output_path: str = "offline_bundle/opencanary-offline.tar.gz",
    python_versions: Optional[List[str]] = None,
    platform: str = "manylinux2014_x86_64",
) -> str:
    """Build the offline installation bundle.

    Steps:
        1. Create temp staging directory
        2. Copy OpenCanary source tree into staging/opencanary-src/
        3. Run ``pip download`` to fetch wheels into staging/wheels/
        4. Copy install.sh into staging root
        5. Copy opencanary.service into staging root
        6. Create .tar.gz archive from staging directory
        7. Write archive to output_path

    Args:
        source_dir: Path to the OpenCanary source tree.
        output_path: Destination path for the .tar.gz archive.
        python_versions: Target Python versions for wheel compatibility.
            Downloads wheels for each version so the bundle works on any.
            Defaults to ["3.10", "3.11", "3.12"].
        platform: Target platform tag for pip download.

    Returns:
        Absolute path to the created archive.

    Raises:
        FileNotFoundError: If source_dir or setup.py not found.
        subprocess.CalledProcessError: If pip download fails.
    """
    if python_versions is None:
        python_versions = ["3.10", "3.11", "3.12"]
    # Validate source directory exists
    if not os.path.isdir(source_dir):
        raise FileNotFoundError(f"OpenCanary source directory not found: {source_dir}")

    setup_py = os.path.join(source_dir, "setup.py")
    if not os.path.isfile(setup_py):
        raise FileNotFoundError(f"setup.py not found in source directory: {setup_py}")

    # Resolve paths for helper files relative to this script
    scripts_dir = os.path.dirname(os.path.abspath(__file__))
    install_sh = os.path.join(scripts_dir, "install.sh")
    service_file = os.path.join(scripts_dir, "opencanary.service")

    staging_dir = tempfile.mkdtemp(prefix="opencanary_bundle_")
    try:
        # 1. Copy OpenCanary source tree into staging/opencanary-src/
        src_dest = os.path.join(staging_dir, "opencanary-src")
        shutil.copytree(source_dir, src_dest)

        # 2. Run pip download to fetch wheels into staging/wheels/
        #    Two passes: binary-only for C-extension packages, then allow source
        #    for pure-Python packages that don't publish wheels.
        wheels_dir = os.path.join(staging_dir, "wheels")
        os.makedirs(wheels_dir, exist_ok=True)

        if BINARY_PACKAGES:
            for pyver in python_versions:
                pip_bin_cmd = [
                    "pip",
                    "download",
                    "--dest", wheels_dir,
                    "--platform", platform,
                    "--python-version", pyver,
                    "--only-binary=:all:",
                ] + BINARY_PACKAGES
                subprocess.run(pip_bin_cmd, check=True)

        if SOURCE_PACKAGES:
            # Download pure-Python packages WITH their dependencies.
            # We don't restrict platform/python-version here because these
            # are pure-Python and work on any platform.
            pip_src_cmd = [
                "pip",
                "download",
                "--dest", wheels_dir,
            ] + SOURCE_PACKAGES
            subprocess.run(pip_src_cmd, check=True)

            # Pre-build any .tar.gz source distributions into wheels so the
            # air-gapped installer doesn't need build tools.
            import glob as _glob
            for sdist in _glob.glob(os.path.join(wheels_dir, "*.tar.gz")):
                try:
                    subprocess.run(
                        ["pip", "wheel", "--no-deps", "--wheel-dir", wheels_dir, sdist],
                        check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                    )
                    os.remove(sdist)  # Remove the .tar.gz, keep only the .whl
                except subprocess.CalledProcessError:
                    pass  # Keep the .tar.gz as fallback

        # Also download pip and setuptools wheels so the manual venv
        # bootstrap (get-pip.py --no-index --find-links) can find them.
        pip_bootstrap_cmd = [
            "pip", "download", "--dest", wheels_dir, "--no-deps",
            "pip", "setuptools<81", "wheel",
        ]
        try:
            subprocess.run(pip_bootstrap_cmd, check=True,
                           stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        except subprocess.CalledProcessError:
            logger.warning("Could not download pip/setuptools wheels — "
                           "get-pip.py will use its embedded copy")

        # 2b. Download .deb packages for offline system dependency install
        debs_dir = os.path.join(staging_dir, "debs")
        try:
            _download_debs(debs_dir)
        except Exception as exc:
            # Non-fatal — the installer will ask the user to install manually
            logger.warning("Failed to download .deb packages: %s", exc)

        # 2c. Download get-pip.py for bootstrapping pip without python3-venv
        try:
            _download_get_pip(staging_dir)
        except Exception as exc:
            logger.warning("Failed to download get-pip.py: %s", exc)

        # 3. Copy install.sh into staging root
        if os.path.isfile(install_sh):
            shutil.copy2(install_sh, os.path.join(staging_dir, "install.sh"))

        # 4. Copy opencanary.service into staging root
        if os.path.isfile(service_file):
            shutil.copy2(service_file, os.path.join(staging_dir, "opencanary.service"))

        # 5. Create .tar.gz archive
        output_path_abs = os.path.abspath(output_path)
        output_dir = os.path.dirname(output_path_abs)
        os.makedirs(output_dir, exist_ok=True)

        with tarfile.open(output_path_abs, "w:gz") as tar:
            for entry in os.listdir(staging_dir):
                entry_path = os.path.join(staging_dir, entry)
                tar.add(entry_path, arcname=entry)

        return output_path_abs

    finally:
        shutil.rmtree(staging_dir, ignore_errors=True)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Build the OpenCanary offline installation bundle."
    )
    parser.add_argument(
        "--source-dir",
        default="opencanary/opencanary-master",
        help="Path to the OpenCanary source tree (default: opencanary/opencanary-master)",
    )
    parser.add_argument(
        "--output",
        default="offline_bundle/opencanary-offline.tar.gz",
        help="Output path for the bundle archive (default: offline_bundle/opencanary-offline.tar.gz)",
    )
    parser.add_argument(
        "--python-version",
        default="3.10,3.11,3.12",
        help="Comma-separated target Python versions for wheel compatibility (default: 3.10,3.11,3.12)",
    )
    parser.add_argument(
        "--platform",
        default="manylinux2014_x86_64",
        help="Target platform tag for pip download (default: manylinux2014_x86_64)",
    )
    args = parser.parse_args()

    try:
        result = build_offline_bundle(
            source_dir=args.source_dir,
            output_path=args.output,
            python_versions=[v.strip() for v in args.python_version.split(",")],
            platform=args.platform,
        )
        print(f"Bundle built successfully: {result}")
    except FileNotFoundError as e:
        print(f"Error: {e}")
        exit(1)
    except subprocess.CalledProcessError as e:
        print(f"Error: pip download failed with exit code {e.returncode}")
        if e.stderr:
            print(e.stderr)
        exit(1)

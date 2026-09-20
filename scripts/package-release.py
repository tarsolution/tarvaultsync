"""Package a native build without credentials, workspaces, or build caches."""

import argparse
import hashlib
from pathlib import Path
import plistlib
import shutil
import tarfile
import tempfile
import tomllib
import zipfile


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--platform", choices=("windows", "macos", "linux"), required=True)
    parser.add_argument("--arch", choices=("amd64", "arm64"), required=True)
    parser.add_argument("--target", required=True)
    args = parser.parse_args()
    version = tomllib.loads(Path("Cargo.toml").read_text(encoding="utf-8"))["package"]["version"]
    name = f"tar-vault-sync-{version}-{args.platform}-{args.arch}"
    binary_name = "tar-vault-sync.exe" if args.platform == "windows" else "tar-vault-sync"
    binary = Path("target") / args.target / "release" / binary_name
    if not binary.is_file():
        raise SystemExit("Release binary is missing")
    output = Path("dist")
    output.mkdir(exist_ok=True)
    with tempfile.TemporaryDirectory() as temporary:
        package = Path(temporary) / name
        package.mkdir()
        if args.platform == "macos":
            contents = package / "TAR Vault Sync.app" / "Contents"
            executable = contents / "MacOS" / binary_name
            executable.parent.mkdir(parents=True)
            with (contents / "Info.plist").open("wb") as stream:
                plistlib.dump({
                    "CFBundleName": "TAR Vault Sync",
                    "CFBundleDisplayName": "TAR Vault Sync",
                    "CFBundleIdentifier": "com.tarsolution.tarvaultsync",
                    "CFBundleExecutable": binary_name,
                    "CFBundlePackageType": "APPL",
                    "CFBundleShortVersionString": version,
                    "CFBundleVersion": version,
                    "NSHighResolutionCapable": True,
                }, stream)
        else:
            executable = package / binary_name
        shutil.copy2(binary, executable)
        executable.chmod(0o755)
        shutil.copy2("docs/release-notes.md", package / "README.md")
        if args.platform == "linux":
            archive = output / f"{name}.tar.gz"
            with tarfile.open(archive, "w:gz") as stream:
                stream.add(package, arcname=name)
        else:
            archive = output / f"{name}.zip"
            with zipfile.ZipFile(archive, "w", compression=zipfile.ZIP_DEFLATED) as stream:
                for path in sorted(package.rglob("*")):
                    if path.is_file():
                        stream.write(path, path.relative_to(package.parent))
        with archive.open("rb") as stream:
            digest = hashlib.file_digest(stream, "sha256").hexdigest()
        (output / f"{archive.name}.sha256").write_text(f"{digest}  {archive.name}\n", encoding="ascii")
        print(f"Packaged {archive.name} ({archive.stat().st_size} bytes)")


if __name__ == "__main__":
    main()

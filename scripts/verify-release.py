"""Require the complete six-platform matrix and matching checksums before publishing."""

import hashlib
from pathlib import Path
import sys


def main():
    folder = Path(sys.argv[1])
    entries = []
    for platform in ("windows", "macos", "linux"):
        for arch in ("amd64", "arm64"):
            extension = "tar.gz" if platform == "linux" else "zip"
            matches = list(folder.glob(f"tar-vault-sync-*-{platform}-{arch}.{extension}"))
            if len(matches) != 1:
                raise SystemExit(f"Expected one {platform}/{arch} package")
            archive = matches[0]
            checksum = folder / f"{archive.name}.sha256"
            expected = checksum.read_text(encoding="ascii").strip()
            with archive.open("rb") as stream:
                actual = hashlib.file_digest(stream, "sha256").hexdigest()
            line = f"{actual}  {archive.name}"
            if expected != line:
                raise SystemExit(f"Checksum mismatch: {archive.name}")
            entries.append(line)
    (folder / "SHA256SUMS").write_text("\n".join(sorted(entries)) + "\n", encoding="ascii")
    print("All six packages and checksums verified")


if __name__ == "__main__":
    main()

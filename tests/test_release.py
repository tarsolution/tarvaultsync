from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
import zipfile


ROOT = Path(__file__).resolve().parents[1]


class ReleasePackagingTests(unittest.TestCase):
    def test_complete_matrix_and_tamper_detection(self):
        with tempfile.TemporaryDirectory() as temporary:
            workspace = Path(temporary)
            (workspace / "Cargo.toml").write_text('[package]\nversion = "0.1.0"\n', encoding="utf-8")
            (workspace / "docs").mkdir()
            (workspace / "docs/release-notes.md").write_text("Test package", encoding="utf-8")
            for platform in ("windows", "macos", "linux"):
                for arch in ("amd64", "arm64"):
                    target = f"test-{platform}-{arch}"
                    folder = workspace / "target" / target / "release"
                    folder.mkdir(parents=True)
                    executable = "tar-vault-sync.exe" if platform == "windows" else "tar-vault-sync"
                    (folder / executable).write_bytes(b"packaging-test-executable")
                    subprocess.run([sys.executable, str(ROOT / "scripts/package-release.py"),
                                    "--platform", platform, "--arch", arch, "--target", target],
                                   cwd=workspace, check=True, capture_output=True)
            verify = [sys.executable, str(ROOT / "scripts/verify-release.py"), str(workspace / "dist")]
            subprocess.run(verify, check=True, capture_output=True)
            self.assertEqual(len((workspace / "dist/SHA256SUMS").read_text().splitlines()), 6)
            mac = workspace / "dist/tar-vault-sync-0.1.0-macos-arm64.zip"
            with zipfile.ZipFile(mac) as archive:
                names = archive.namelist()
                self.assertTrue(any(name.endswith(".app/Contents/Info.plist") for name in names))
                binary = next(item for item in archive.infolist() if item.filename.endswith("/MacOS/tar-vault-sync"))
                self.assertTrue((binary.external_attr >> 16) & 0o111)
            with mac.open("ab") as stream:
                stream.write(b"corrupt")
            self.assertNotEqual(subprocess.run(verify, capture_output=True).returncode, 0)
            mac.unlink()
            self.assertNotEqual(subprocess.run(verify, capture_output=True).returncode, 0)


if __name__ == "__main__":
    unittest.main()

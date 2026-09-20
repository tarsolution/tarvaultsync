# Release and contributor catalogue

The documentation is static, including `releases.html` and `credits.html`.
Refresh public GitHub metadata with:

```sh
python scripts/update-docs-catalog.py
python -m unittest discover -s tests
```

Commit the two generated HTML pages and push the documentation branch to
publish them through the existing GitHub Pages deployment. Run this refresh
after publishing, editing or deleting a release. It can also run during a
future release pipeline before the documentation deployment; automatic
release-triggered refresh is not configured yet.

The latest section selects the most recently published non-draft,
non-prerelease release. The archive contains the remaining published
releases, newest first, with pre-releases labelled. Download links point to
the authoritative GitHub release page. No release is created by this script.

Contributor metadata comes from GitHub's public contributor list and public
profiles. Bots appear separately. GitHub may cache this list and may omit
non-code or unattributed contributions. No email addresses or credentials are
stored. API failures stop generation rather than producing an empty catalogue.

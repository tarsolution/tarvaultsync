# Reproduce the documentation screenshots

The six guide images are actual native egui screens rendered with an isolated,
synthetic workspace. They contain no account credentials or secret values and
are not evidence of cloud integration or Windows/macOS interactive acceptance.

On Linux, install Xvfb, Mesa/OpenGL, `libxkbcommon-x11-0`, X11 runtime libraries
and ImageMagick, then run:

```sh
TAR_VAULT_DOC_OUTPUT="$PWD/target/doc-captures" \
  xvfb-run -a -s '-screen 0 1440x1800x24' \
  cargo test --locked --lib desktop::tests::render_documentation_screens -- \
  --ignored --exact
for page in overview sources vault bindings activity settings; do
  magick "target/doc-captures/$page.ppm" "docs/assets/$page.png"
done
python3 -m unittest discover -s tests -p 'test_*.py'
```

The capture test is ignored in normal unit runs because it needs a graphical
backend. It renders the application directly; it never imports a browser
profile, unlocks a real vault, or contacts a cloud provider. Review every PNG
before committing. Do not publish screenshots from a real workspace.

The static site is `docs/index.html`; no build framework or client JavaScript is
needed. GitHub Pages should publish this directory. Its intended custom domain
is `tarvault.tarsolution.com`. Publishing documentation does not publish an app
release or satisfy any release acceptance gate.

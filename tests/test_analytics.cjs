const { test } = require("node:test");
const assert = require("node:assert/strict");
const { readFileSync } = require("node:fs");
const vm = require("node:vm");
const source = readFileSync(new URL("../docs/assets/analytics.js", "file://" + __filename.replaceAll("\\", "/")), "utf8");

function run(hostname = "tarvault.tarsolution.com", saved = null) {
  const elements = [];
  const node = () => ({
    style: {}, children: [], handlers: {},
    setAttribute() {}, append(...items) { this.children.push(...items); },
    addEventListener(event, handler) { this.handlers[event] = handler; }
  });
  const document = { head: node(), body: node(), cookie: "",
    createElement(tag) { const el = node(); el.tag = tag; elements.push(el); return el; } };
  const window = {};
  const localStorage = { getItem() { return saved; }, setItem(key, value) { saved = value; } };
  vm.runInNewContext(source, { document, window, localStorage,
    location: { hostname, origin: "https://" + hostname, pathname: "/releases.html",
      search: "?private=example", hash: "#private" } });
  return { document, window, click(label) {
    elements.find(el => el.textContent === label).handlers.click();
  } };
}

test("no Google request before consent, or on local/private Sites copies", () => {
  for (const [host, choice] of [["localhost", "accepted"], ["tar-vault-sync.fmarslan.chatgpt.site", "accepted"],
    ["tarvault.tarsolution.com", null], ["tarvault.tarsolution.com", "declined"]]) {
    assert.equal(run(host, choice).document.head.children.length, 0);
  }
});

test("acceptance loads once, strips URL parameters, and supports withdrawal", () => {
  const app = run();
  app.click("Allow analytics");
  app.click("Allow analytics");
  assert.equal(app.document.head.children.length, 1);
  assert.match(app.document.head.children[0].src, /id=G-MG2LD1T304$/);
  const config = app.window.dataLayer.find(args => args[0] === "config")[2];
  assert.equal(config.page_location, "https://tarvault.tarsolution.com/releases.html");
  assert.equal(config.page_referrer, "");
  assert.equal(config.allow_google_signals, false);
  app.click("Decline");
  assert.equal(app.window["ga-disable-G-MG2LD1T304"], true);
  app.click("Allow analytics");
  assert.equal(app.window["ga-disable-G-MG2LD1T304"], false);
  assert.equal(app.document.head.children.length, 1);
  assert.equal(run("tarvault.tarsolution.com", "accepted").document.head.children.length, 1);
});

/* Website analytics only. Never loaded by the native vault application. */
(() => {
  "use strict";
  if (location.hostname !== "tarvault.tarsolution.com") return;
  const measurementId = "G-MG2LD1T304";
  const storageKey = "tarvault-analytics-consent";
  let started = false;
  function start() {
    if (started) return;
    started = true;
    window.dataLayer = window.dataLayer || [];
    window.gtag = function () { window.dataLayer.push(arguments); };
    window.gtag("consent", "default", {
      analytics_storage: "granted", ad_storage: "denied",
      ad_user_data: "denied", ad_personalization: "denied"
    });
    window.gtag("js", new Date());
    window.gtag("config", measurementId, {
      page_location: location.origin + location.pathname,
      page_referrer: "",
      cookie_domain: "tarvault.tarsolution.com",
      allow_google_signals: false,
      allow_ad_personalization_signals: false
    });
    const tag = document.createElement("script");
    tag.async = true;
    tag.src = "https://www.googletagmanager.com/gtag/js?id=" + measurementId;
    document.head.append(tag);
  }
  let choice;
  try { choice = localStorage.getItem(storageKey); } catch (_) { /* Storage may be blocked. */ }
  if (choice === "accepted") start();
  const panel = document.createElement("section");
  panel.setAttribute("aria-label", "Website analytics preference");
  panel.style.cssText = "position:fixed;bottom:16px;right:16px;z-index:1000;max-width:360px;padding:16px;background:#fff;color:#132030;border:1px solid #cbd5e1;border-radius:12px;box-shadow:0 4px 20px #13203020;font:14px/1.5 system-ui";
  const message = document.createElement("p");
  message.textContent = "Allow Google Analytics cookies to measure visits to this documentation site? Vault contents are never included.";
  panel.append(message);
  const preference = document.createElement("button");
  preference.type = "button";
  preference.textContent = "Analytics preferences";
  preference.style.cssText = "position:fixed;bottom:8px;right:8px;z-index:999;background:#fff;color:#132030;border:1px solid #cbd5e1;border-radius:6px;padding:6px 10px;font:12px system-ui;cursor:pointer";
  preference.addEventListener("click", () => { panel.hidden = false; preference.hidden = true; });
  for (const [label, value] of [["Allow analytics", "accepted"], ["Decline", "declined"]]) {
    const button = document.createElement("button");
    button.type = "button";
    button.textContent = label;
    button.style.cssText = "margin-right:8px;padding:8px 12px;border:1px solid #0f766e;border-radius:6px;background:#fff;color:#0f766e;cursor:pointer";
    button.addEventListener("click", () => {
      try { localStorage.setItem(storageKey, value); } catch (_) { /* Respect the choice for this page. */ }
      window["ga-disable-" + measurementId] = value !== "accepted";
      if (value === "accepted") {
        if (started) window.gtag("consent", "update", { analytics_storage: "granted" });
        start();
      } else {
        if (window.gtag) window.gtag("consent", "update", { analytics_storage: "denied" });
        for (const cookie of document.cookie.split(";")) {
          const name = cookie.split("=")[0].trim();
          if (name === "_ga" || name.startsWith("_ga_")) {
            for (const domain of ["", "; domain=tarvault.tarsolution.com"]) {
              document.cookie = name + "=; Max-Age=0; path=/" + domain;
            }
          }
        }
      }
      panel.hidden = true;
      preference.hidden = false;
    });
    panel.append(button);
  }
  panel.hidden = choice === "accepted" || choice === "declined";
  preference.hidden = !panel.hidden;
  document.body.append(panel, preference);
})();

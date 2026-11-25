// The report form. Nothing is sent until Send is pressed, and only what is typed on the page.
(function () {
  "use strict";
  const API = "https://nnftdhyfjfzjalxvhhmz.supabase.co/rest/v1/reports";
  // Publishable key: with it a browser can add a report and nothing else (no reading, no editing).
  const KEY = "sb_publishable_GmfMb8KIIOhId1TNGEuK0A_0HvIhKcD";
  const $ = (id) => document.getElementById(id);

  // The app opens this page as /report?kind=false_alarm&v=0.4.1; both are checked before use.
  const params = new URLSearchParams(location.search);
  if ([...$("kind").options].some((o) => o.value === params.get("kind"))) $("kind").value = params.get("kind");
  const version = /^[0-9A-Za-z.+-]{1,40}$/.test(params.get("v") || "") ? params.get("v") : null;
  if (version) $("version-note").textContent = `App version ${version} will be included.`;

  const say = (text, bad) => {
    $("form-status").textContent = text;
    $("form-status").classList.toggle("bad", Boolean(bad));
  };
  const done = () => {
    $("form").hidden = true;
    $("thanks").classList.add("on");
  };

  $("form").addEventListener("submit", async (event) => {
    event.preventDefault();
    const message = $("message").value.trim();
    if (message.length < 10) {
      say("Please describe the problem in at least 10 characters.", true);
      $("message").focus();
      return;
    }
    if ($("website").value) return done(); // only a bot fills the hidden field; drop it quietly
    $("send").disabled = true;
    say("Sending…");
    try {
      const response = await fetch(API, {
        method: "POST",
        headers: { apikey: KEY, "Content-Type": "application/json", Prefer: "return=minimal" },
        body: JSON.stringify({
          kind: $("kind").value,
          message,
          details: $("details").value.trim() || null,
          contact: $("contact").value.trim() || null,
          app_version: version,
        }),
      });
      if (response.ok) return done();
      const problem = await response.json().catch(() => ({}));
      say(problem.code === "P0001" ? "Too many reports today. Please try again tomorrow." : "The report could not be sent. Please try again later.", true);
    } catch {
      say("The report could not be sent. Check your connection and try again.", true);
    }
    $("send").disabled = false;
  });
})();

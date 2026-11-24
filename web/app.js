// Supabase email links put the session (or an error) in the URL hash. This page only reads
// whether it succeeded to choose a message, then wipes the hash. Tokens are never stored,
// logged or sent anywhere: the user signs in inside the app.
(function () {
  "use strict";
  const $ = (id) => document.getElementById(id);
  const params = new URLSearchParams(location.hash.slice(1));
  if (location.hash) history.replaceState(null, "", location.pathname + location.search);

  const show = (title, body) => {
    $("status-title").textContent = title;
    $("status-body").textContent = body;
    $("open").hidden = false;
    $("status").classList.add("on");
    document.title = title + " - The Nex";
  };

  if (params.has("error") || params.has("error_code")) {
    // Fixed text only: the hash comes from the link, so anyone could craft its wording.
    const expired = params.get("error_code") === "otp_expired";
    show(
      expired ? "This link has expired" : "This link didn't work",
      (expired ? "Confirmation links only work once and expire after a while. " : "") +
        "Open The Nex and sign up again to get a new email."
    );
  } else if (params.has("access_token")) {
    show(
      "You're all set",
      "Your email is confirmed. Open The Nex and sign in with the same email and password to see your dashboard."
    );
  }

  $("open").addEventListener("click", () => {
    // If no app picks up thenex://, the page stays visible; say what to do instead.
    setTimeout(() => {
      if (document.visibilityState === "visible") {
        $("hint").textContent =
          "Nothing opened? Open The Nex from your Applications folder (Mac) or the Start menu (Windows), then sign in.";
      }
    }, 1500);
  });

  // Download control: stays a disabled button until data-download-url holds an https link.
  const btn = $("download-btn");
  const url = (btn.dataset.downloadUrl || "").trim();
  if (/^https:\/\//.test(url)) {
    const a = document.createElement("a");
    a.className = "btn";
    a.id = btn.id;
    a.href = url;
    a.rel = "noopener noreferrer";
    a.textContent = "Download for Mac";
    btn.replaceWith(a);
  }
})();

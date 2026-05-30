package gtunnel

import "strings"

// GenWorkerJS returns a self-contained Cloudflare Worker that accepts the relay
// JSON {u,m,h,b,ct,r}, performs the fetch, and returns {s,h,b}. workerHost is
// the worker's own hostname (used to block self-fetch loops). This is our own
// implementation, generated for the user to paste into their Worker.
func GenWorkerJS(workerHost string) string {
	if strings.TrimSpace(workerHost) == "" {
		workerHost = "myworker.workers.dev"
	}
	s := `// V2RayEz — Google Tunnel exit Worker
// Receives a relayed request as JSON, fetches the target, returns the response.
// Deploy at Cloudflare → Workers & Pages. No configuration needed beyond the
// hostname below (used only to block self-fetch loops).
const WORKER_HOST = "%HOST%";

export default {
  async fetch(request) {
    try {
      if (request.headers.get("x-relay-hop") === "1")
        return json({ e: "loop detected" }, 508);
      if (request.method === "GET")
        return json({ e: "V2RayEz relay worker active." }, 200);
      if (request.method !== "POST")
        return json({ e: "method not allowed" }, 405);

      const req = await request.json();
      if (!req.u || !/^https?:\/\//i.test(req.u))
        return json({ e: "bad or missing url" }, 400);

      const target = new URL(req.u);
      if (target.hostname.endsWith(WORKER_HOST))
        return json({ e: "self-fetch blocked" }, 400);

      const headers = new Headers();
      if (req.h && typeof req.h === "object")
        for (const [k, v] of Object.entries(req.h)) headers.set(k, v);
      headers.set("x-relay-hop", "1");

      const opts = {
        method: (req.m || "GET").toUpperCase(),
        headers,
        redirect: req.r === false ? "manual" : "follow",
      };
      if (req.b) opts.body = Uint8Array.from(atob(req.b), c => c.charCodeAt(0));

      const resp = await fetch(target.toString(), opts);
      const buf = new Uint8Array(await resp.arrayBuffer());
      let bin = "";
      const CH = 0x8000;
      for (let i = 0; i < buf.length; i += CH)
        bin += String.fromCharCode.apply(null, buf.subarray(i, i + CH));

      const h = {};
      resp.headers.forEach((v, k) => { h[k] = v; });
      return json({ s: resp.status, h, b: btoa(bin) });
    } catch (err) {
      return json({ e: String(err) }, 500);
    }
  },
};

function json(obj, status = 200) {
  return new Response(JSON.stringify(obj), {
    status, headers: { "content-type": "application/json" },
  });
}
`
	return strings.ReplaceAll(s, "%HOST%", workerHost)
}

// GenCodeGS returns a Google Apps Script web app that authenticates with
// authKey and forwards relay requests to the given Cloudflare Worker URL.
// Our own implementation for the user to paste into Apps Script.
func GenCodeGS(authKey, workerURL string) string {
	if strings.TrimSpace(authKey) == "" {
		authKey = "change-this-secret"
	}
	if strings.TrimSpace(workerURL) == "" {
		workerURL = "https://myworker.workers.dev"
	}
	if !strings.HasPrefix(workerURL, "http") {
		workerURL = "https://" + workerURL
	}
	s := `/**
 * V2RayEz — Google Tunnel relay (Google Apps Script web app)
 * Client (front-domain) -> this GAS -> Cloudflare Worker -> target
 * Deploy: Deploy > New deployment > Web app > Execute as: Me, Access: Anyone.
 * Use the SAME auth key here and in the V2RayEz app.
 */
const AUTH_KEY   = "%AUTH%";
const WORKER_URL = "%WORKER%";
const SKIP = { host:1, connection:1, "content-length":1, "transfer-encoding":1, "proxy-connection":1, "proxy-authorization":1 };

function doPost(e) {
  try {
    const req = JSON.parse(e.postData.contents);
    if (req.k !== AUTH_KEY) return _json({ e: "unauthorized" });
    if (!req.u || !/^https?:\/\//i.test(req.u)) return _json({ e: "bad url" });

    const headers = {};
    if (req.h && typeof req.h === "object")
      for (const k in req.h)
        if (!SKIP[k.toLowerCase()]) headers[k] = req.h[k];

    const payload = {
      u: req.u, m: (req.m || "GET").toUpperCase(),
      h: headers, b: req.b || null, ct: req.ct || null, r: req.r !== false,
    };
    const resp = UrlFetchApp.fetch(WORKER_URL, {
      method: "post", contentType: "application/json",
      payload: JSON.stringify(payload), muteHttpExceptions: true, followRedirects: true,
    });
    try { return _json(JSON.parse(resp.getContentText())); }
    catch (err) { return _json({ e: "bad worker response", raw: resp.getContentText() }); }
  } catch (err) {
    return _json({ e: String(err) });
  }
}

function doGet() {
  return HtmlService.createHtmlOutput("<h3>V2RayEz relay active</h3>");
}

function _json(o) {
  return ContentService.createTextOutput(JSON.stringify(o)).setMimeType(ContentService.MimeType.JSON);
}
`
	s = strings.ReplaceAll(s, "%AUTH%", authKey)
	s = strings.ReplaceAll(s, "%WORKER%", workerURL)
	return s
}

// Cloudflare Worker CHAT ID: (1) kirim push notifikasi FCM  (2) reset password oleh akun admin
// Secret wajib di Cloudflare:  SA_JSON = isi file service account Firebase (JSON utuh)
//                              API_KEY = nilai apiKey dari firebaseConfig di file HTML
const PROJECT = "vanzz-area";
const DB = "https://vanzz-area-default-rtdb.firebaseio.com";
const DOMAIN = "@id.vanzzarea.local";
const ADMIN_EMAIL = "akunadmin" + DOMAIN;
const cors = { "Access-Control-Allow-Origin": "*", "Access-Control-Allow-Headers": "Content-Type, Authorization", "Access-Control-Allow-Methods": "POST, OPTIONS" };
const json = (o, s = 200) => new Response(JSON.stringify(o), { status: s, headers: { ...cors, "Content-Type": "application/json" } });
const cleanId = s => String(s || "").trim().toLowerCase().replace(/[^a-z0-9_.-]/g, "");
const safeKey = s => /^[A-Za-z0-9_-]{3,120}$/.test(String(s || ""));
const b64u = b => btoa(String.fromCharCode(...new Uint8Array(b))).replace(/=/g, "").replace(/\+/g, "-").replace(/\//g, "_");
const b64uStr = s => b64u(new TextEncoder().encode(s));

let cache = { t: "", exp: 0 };
async function saToken(env) {
  if (cache.t && Date.now() < cache.exp) return cache.t;
  const sa = JSON.parse(env.SA_JSON), now = Math.floor(Date.now() / 1000);
  const head = b64uStr(JSON.stringify({ alg: "RS256", typ: "JWT" }));
  const claim = b64uStr(JSON.stringify({
    iss: sa.client_email,
    scope: "https://www.googleapis.com/auth/cloud-platform https://www.googleapis.com/auth/firebase.database https://www.googleapis.com/auth/userinfo.email https://www.googleapis.com/auth/firebase.messaging",
    aud: "https://oauth2.googleapis.com/token", iat: now, exp: now + 3300
  }));
  const pem = sa.private_key.replace(/-----[^-]+-----/g, "").replace(/\s+/g, "");
  const key = await crypto.subtle.importKey("pkcs8", Uint8Array.from(atob(pem), c => c.charCodeAt(0)), { name: "RSASSA-PKCS1-v1_5", hash: "SHA-256" }, false, ["sign"]);
  const sig = await crypto.subtle.sign("RSASSA-PKCS1-v1_5", key, new TextEncoder().encode(head + "." + claim));
  const r = await fetch("https://oauth2.googleapis.com/token", { method: "POST", headers: { "Content-Type": "application/x-www-form-urlencoded" }, body: "grant_type=urn%3Aietf%3Aparams%3Aoauth%3Agrant-type%3Ajwt-bearer&assertion=" + head + "." + claim + "." + b64u(sig) });
  const d = await r.json();
  if (!d.access_token) throw new Error("Token service account gagal");
  cache = { t: d.access_token, exp: Date.now() + 3000 * 1000 };
  return cache.t;
}
const dbGet = async (path, tk) => { const r = await fetch(DB + "/" + path + ".json", { headers: { Authorization: "Bearer " + tk } }); return r.ok ? r.json() : null; };
const dbDel = (path, tk) => fetch(DB + "/" + path + ".json", { method: "DELETE", headers: { Authorization: "Bearer " + tk } });

async function sendFcm(tk, token, n) {
  const r = await fetch("https://fcm.googleapis.com/v1/projects/" + PROJECT + "/messages:send", {
    method: "POST", headers: { Authorization: "Bearer " + tk, "Content-Type": "application/json" },
    body: JSON.stringify({ message: { token, notification: { title: n.title, body: n.body }, data: n.data, android: { priority: "HIGH", notification: { channel_id: n.channel, tag: n.tag, sound: "default" } } } })
  });
  if (r.ok) return "ok";
  const e = await r.json().catch(() => ({})), st = e.error && e.error.status;
  return (st === "NOT_FOUND" || st === "UNREGISTERED") ? "dead" : "err";
}
async function pushTo(uids, n, tk) {
  for (const uid of uids) {
    const toks = (await dbGet("userData/" + uid + "/fcmTokens", tk)) || {};
    for (const [k, v] of Object.entries(toks)) {
      if (!v || !v.t) continue;
      const res = await sendFcm(tk, v.t, n(uid));
      if (res === "dead") await dbDel("userData/" + uid + "/fcmTokens/" + k, tk);
    }
  }
}

export default {
  async fetch(req, env) {
    if (req.method === "OPTIONS") return new Response(null, { headers: cors });
    if (req.method !== "POST") return json({ error: "Metode tidak didukung" }, 405);
    try {
      const idToken = (req.headers.get("Authorization") || "").replace(/^Bearer\s+/i, "");
      if (!idToken) return json({ error: "Tidak ada token" }, 401);
      const who = await (await fetch("https://identitytoolkit.googleapis.com/v1/accounts:lookup?key=" + env.API_KEY, { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ idToken }) })).json();
      const me = who && who.users && who.users[0];
      if (!me) return json({ error: "Token tidak valid" }, 401);
      const body = await req.json();
      const tk = await saToken(env);

      // ---------- reset password (khusus akun admin) ----------
      if (body.password !== undefined) {
        if (me.email !== ADMIN_EMAIL) return json({ error: "Hanya akun admin yang boleh reset password" }, 403);
        const id = cleanId(body.id), pw = String(body.password || "");
        if (!id) return json({ error: "ID kosong" }, 400);
        if (pw.length < 6 || pw.length > 100) return json({ error: "Password 6-100 karakter" }, 400);
        const H = { "Content-Type": "application/json", Authorization: "Bearer " + tk };
        const base = "https://identitytoolkit.googleapis.com/v1/projects/" + PROJECT;
        const f = await (await fetch(base + "/accounts:lookup", { method: "POST", headers: H, body: JSON.stringify({ email: [id + DOMAIN] }) })).json();
        const localId = f && f.users && f.users[0] && f.users[0].localId;
        if (!localId) return json({ error: "ID @" + id + " tidak ditemukan" }, 404);
        const u = await fetch(base + "/accounts:update", { method: "POST", headers: H, body: JSON.stringify({ localId, password: pw }) });
        if (!u.ok) { const e = await u.json().catch(() => ({})); return json({ error: (e.error && e.error.message) || "Gagal mengubah password" }, 500); }
        return json({ ok: true });
      }

      // ---------- push notifikasi ----------
      const sender = me.localId;
      const prof = (await dbGet("users/" + sender, tk)) || {};
      const myName = prof.displayName || prof.id || "Pengguna", myId = prof.id || "";

      if (body.kind === "call") {
        const to = String(body.toUid || "");
        if (!safeKey(to) || to === sender) return json({ ok: true });
        await pushTo([to], () => ({ title: "Panggilan masuk", body: myName + " sedang memanggilmu", channel: "call", tag: "call-" + sender, data: { kind: "call", key: myId, ctype: "user" } }), tk);
        return json({ ok: true });
      }

      if (body.kind === "msg") {
        const chatKey = String(body.chatKey || ""), msgId = String(body.msgId || "");
        if (!safeKey(chatKey) || !safeKey(msgId)) return json({ error: "Data tidak valid" }, 400);
        const m = await dbGet("messages/" + chatKey + "/" + msgId, tk);
        if (!m || m.senderUid !== sender) return json({ error: "Pesan tidak ditemukan" }, 404);
        let list = [], group = null;
        const g = await dbGet("groups/" + chatKey, tk);
        if (g && g.members) { group = g; list = Object.keys(g.members).filter(u => u !== sender); }
        else { const p = chatKey.split("_"); if (p.length === 2 && p.includes(sender)) list = p.filter(u => u !== sender); }
        if (!list.length) return json({ ok: true });
        const text = String(m.text || (m.type === "sticker" ? "Stiker" : m.type === "image" ? "Foto" : m.type === "video" ? "Video" : "Pesan baru")).slice(0, 140);
        const tagged = new Set(Array.isArray(body.mentions) ? body.mentions.map(String) : []);
        await pushTo(list, uid => ({
          title: group ? (group.name || "Grup") : myName,
          body: (tagged.has(uid) ? "📣 Kamu di-tag • " : "") + (group ? myName + ": " : "") + text,
          channel: "chat", tag: "chat-" + chatKey,
          data: { kind: "msg", key: group ? chatKey : myId, ctype: group ? "group" : "user" }
        }), tk);
        return json({ ok: true });
      }
      return json({ error: "Permintaan tidak dikenal" }, 400);
    } catch (e) { return json({ error: "Kesalahan server: " + (e.message || e) }, 500); }
  }
};

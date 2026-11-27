// 한줄 불경 기록 보관 서버 (Cloudflare Worker)
// 카카오 로그인 → 세션 토큰 발급 → 사용자 기록(JSON)을 KV에 보관
const APP_ORIGIN = "https://sutra.dualtimestudio.com";
const API_ORIGIN = "https://api.dualtimestudio.com";
const REDIRECT = API_ORIGIN + "/kakao/callback";
const G_REDIRECT = API_ORIGIN + "/google/callback";
const MAX_BYTES = 512 * 1024;
const SESSION_DAYS = 365;

const enc = new TextEncoder();
const b64u = (buf) => btoa(String.fromCharCode(...new Uint8Array(buf))).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");

async function hmac(secret, msg) {
  const key = await crypto.subtle.importKey("raw", enc.encode(secret), { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
  return b64u(await crypto.subtle.sign("HMAC", key, enc.encode(msg)));
}
async function makeToken(env, uid) {
  const exp = Math.floor(Date.now() / 1000) + SESSION_DAYS * 86400;
  const body = uid + "." + exp;
  return body + "." + (await hmac(env.SESSION_SECRET, body));
}
async function readToken(env, req) {
  const h = req.headers.get("Authorization") || "";
  const t = h.startsWith("Bearer ") ? h.slice(7) : "";
  const p = t.split(".");
  if (p.length !== 3) return null;
  const [uid, exp, sig] = p;
  if (+exp < Date.now() / 1000) return null;
  if ((await hmac(env.SESSION_SECRET, uid + "." + exp)) !== sig) return null;
  const u = await env.KV.get("u:" + uid, "json");
  return u ? { uid, ...u } : null;
}

function cors(req) {
  const o = req.headers.get("Origin") || "";
  const ok = o === APP_ORIGIN || /^http:\/\/localhost(:\d+)?$/.test(o);
  return {
    "Access-Control-Allow-Origin": ok ? o : APP_ORIGIN,
    "Access-Control-Allow-Methods": "GET,PUT,POST,DELETE,OPTIONS",
    "Access-Control-Allow-Headers": "Authorization,Content-Type",
    "Access-Control-Max-Age": "86400",
    Vary: "Origin",
  };
}
const json = (req, data, status = 200) =>
  new Response(JSON.stringify(data), { status, headers: { "Content-Type": "application/json; charset=utf-8", "Cache-Control": "no-store", ...cors(req) } });

function safeReturn(r) {
  try {
    const u = new URL(r || APP_ORIGIN + "/");
    if (u.origin === APP_ORIGIN) return u.origin + u.pathname + u.search;
  } catch (e) {}
  return APP_ORIGIN + "/";
}

async function finishLogin(env, ret, uid, nick, via) {
  const prev = (await env.KV.get("u:" + uid, "json")) || {};
  await env.KV.put("u:" + uid, JSON.stringify({ nick, via, created: prev.created || Date.now(), last: Date.now() }));
  const token = await makeToken(env, uid);
  return Response.redirect(ret + "#login=" + encodeURIComponent(token) + "&nick=" + encodeURIComponent(nick) + "&via=" + via, 302);
}
async function logErr(env, step, status, body) {
  await env.KV.put("err:last", JSON.stringify({ at: Date.now(), step, status, body }), { expirationTtl: 86400 * 7 });
}


// ---------- 편지 알림 (Web Push) ----------
// 비밀값: VAPID_PRIVATE_JWK (JSON 문자열). 크론: */5 * * * *
const VAPID_PUBLIC = "BFmppyUlh7v6OhpKVP1aQXNmAb-uZ1ZjoNrN3gZJuC9StfJoEQYzIRl1BCt85EYwbrlxrupMBV1Yn7wYHy8xwqc";
const VAPID_SUB = "mailto:hello@dualtimestudio.com";
const SLOTS = ["am", "pm", "ev"];
const unb64u = (s) => Uint8Array.from(atob(s.replace(/-/g, "+").replace(/_/g, "/") + "===".slice((s.length + 3) % 4)), (c) => c.charCodeAt(0));
const cat = (...a) => { const o = new Uint8Array(a.reduce((n, x) => n + x.length, 0)); let i = 0; for (const x of a) { o.set(x, i); i += x.length; } return o; };
async function hkdf(salt, ikm, info, len) {
  const k = await crypto.subtle.importKey("raw", ikm, "HKDF", false, ["deriveBits"]);
  return new Uint8Array(await crypto.subtle.deriveBits({ name: "HKDF", hash: "SHA-256", salt, info }, k, len * 8));
}
async function encryptPush(sub, text) {
  const ua = unb64u(sub.keys.p256dh), auth = unb64u(sub.keys.auth);
  const kp = await crypto.subtle.generateKey({ name: "ECDH", namedCurve: "P-256" }, true, ["deriveBits"]);
  const as = new Uint8Array(await crypto.subtle.exportKey("raw", kp.publicKey));
  const uaKey = await crypto.subtle.importKey("raw", ua, { name: "ECDH", namedCurve: "P-256" }, false, []);
  const shared = new Uint8Array(await crypto.subtle.deriveBits({ name: "ECDH", public: uaKey }, kp.privateKey, 256));
  const ikm = await hkdf(auth, shared, cat(enc.encode("WebPush: info\0"), ua, as), 32);
  const salt = crypto.getRandomValues(new Uint8Array(16));
  const cek = await hkdf(salt, ikm, enc.encode("Content-Encoding: aes128gcm\0"), 16);
  const nonce = await hkdf(salt, ikm, enc.encode("Content-Encoding: nonce\0"), 12);
  const key = await crypto.subtle.importKey("raw", cek, "AES-GCM", false, ["encrypt"]);
  const ct = new Uint8Array(await crypto.subtle.encrypt({ name: "AES-GCM", iv: nonce }, key, cat(enc.encode(text), new Uint8Array([2]))));
  const rs = new Uint8Array([0, 0, 16, 0]);
  return cat(salt, rs, new Uint8Array([as.length]), as, ct);
}
let vapidKey = null;
async function vapidAuth(env, endpoint) {
  if (!vapidKey) vapidKey = await crypto.subtle.importKey("jwk", JSON.parse(env.VAPID_PRIVATE_JWK), { name: "ECDSA", namedCurve: "P-256" }, false, ["sign"]);
  const aud = new URL(endpoint).origin;
  const h = b64u(enc.encode(JSON.stringify({ typ: "JWT", alg: "ES256" })));
  const p = b64u(enc.encode(JSON.stringify({ aud, exp: Math.floor(Date.now() / 1000) + 12 * 3600, sub: VAPID_SUB })));
  const sig = await crypto.subtle.sign({ name: "ECDSA", hash: "SHA-256" }, vapidKey, enc.encode(h + "." + p));
  return "vapid t=" + h + "." + p + "." + b64u(sig) + ", k=" + VAPID_PUBLIC;
}
async function sendPush(env, sub, data, ttl = 6 * 3600) {
  const body = await encryptPush(sub, JSON.stringify(data));
  const r = await fetch(sub.endpoint, {
    method: "POST",
    headers: { Authorization: await vapidAuth(env, sub.endpoint), "Content-Encoding": "aes128gcm", "Content-Type": "application/octet-stream", TTL: String(ttl), Urgency: "normal" },
    body,
  });
  return r.status;
}
const pushId = async (endpoint) => b64u(await crypto.subtle.digest("SHA-256", enc.encode(endpoint))).slice(0, 22);
function localNow(tz) {
  let p;
  try { p = Object.fromEntries(new Intl.DateTimeFormat("en-CA", { timeZone: tz, year: "numeric", month: "2-digit", day: "2-digit", hour: "2-digit", minute: "2-digit", hourCycle: "h23" }).formatToParts(new Date()).map((x) => [x.type, x.value])); }
  catch (e) { return localNow("Asia/Seoul"); }
  return { d: p.year + "-" + p.month + "-" + p.day, m: +p.hour * 60 + +p.minute };
}
const hm = (t) => { const a = String(t || "").split(":"); return +a[0] * 60 + +a[1]; };
async function pushApi(req, env, path) {
  let b; try { b = await req.json(); } catch (e) { return json(req, { error: "bad_json" }, 400); }
  const sub = b && b.sub;
  if (!sub || typeof sub.endpoint !== "string" || !/^https:\/\//.test(sub.endpoint) || sub.endpoint.length > 1000) return json(req, { error: "bad_sub" }, 400);
  const id = await pushId(sub.endpoint);
  const idx = (await env.KV.get("push:index", "json")) || {};
  if (path === "/push/unsub") { if (idx[id]) { delete idx[id]; await env.KV.put("push:index", JSON.stringify(idx)); } return json(req, { ok: true }); }
  if (path === "/push/sub") {
    if (!sub.keys || !sub.keys.p256dh || !sub.keys.auth) return json(req, { error: "bad_keys" }, 400);
    const slots = {};
    for (const k of SLOTS) { const t = b.slots && b.slots[k]; slots[k] = typeof t === "string" && /^\d{1,2}:\d{2}$/.test(t) ? t : null; }
    const tz = typeof b.tz === "string" && b.tz.length < 64 ? b.tz : "Asia/Seoul";
    const prev = idx[id];
    const rec = { e: sub.endpoint, k: { p256dh: sub.keys.p256dh, auth: sub.keys.auth }, s: slots, tz, at: Date.now() };
    if (!prev || JSON.stringify({ ...prev, at: 0 }) !== JSON.stringify({ ...rec, at: 0 })) { idx[id] = rec; await env.KV.put("push:index", JSON.stringify(idx)); }
    return json(req, { ok: true, id });
  }
  if (path === "/push/test") {
    const r = idx[id]; if (!r) return json(req, { error: "not_subscribed" }, 404);
    const slot = SLOTS.includes(b.slot) ? b.slot : "am";
    const st = await sendPush(env, { endpoint: r.e, keys: r.k }, { slot, d: localNow(r.tz).d, test: 1 }, 600);
    return json(req, { ok: st < 300, status: st });
  }
  return json(req, { error: "not_found" }, 404);
}
async function runPush(env) {
  const idx = (await env.KV.get("push:index", "json")) || {};
  const sent = (await env.KV.get("push:sent", "json")) || {};
  let dirtyS = false, dirtyI = false, n = 0;
  const jobs = [];
  for (const [id, r] of Object.entries(idx)) {
    const now = localNow(r.tz);
    for (const k of SLOTS) {
      const t = r.s && r.s[k]; if (!t) continue;
      const due = hm(t), key = id + ":" + k;
      if (now.m >= due && now.m < due + 30 && sent[key] !== now.d) {
        sent[key] = now.d; dirtyS = true;
        jobs.push(sendPush(env, { endpoint: r.e, keys: r.k }, { slot: k, d: now.d }).then((st) => { n++; if (st === 404 || st === 410) { delete idx[id]; dirtyI = true; } }).catch(() => {}));
      }
    }
  }
  await Promise.all(jobs);
  if (dirtyS) await env.KV.put("push:sent", JSON.stringify(sent));
  if (dirtyI) await env.KV.put("push:index", JSON.stringify(idx));
  return n;
}

export default {
  async scheduled(event, env, ctx) { ctx.waitUntil(runPush(env)); },
  async fetch(req, env) {
    const url = new URL(req.url);
    const path = url.pathname;
    if (req.method === "OPTIONS") return new Response(null, { status: 204, headers: cors(req) });

    if (path === "/" || path === "/health") return json(req, { ok: true, service: "hanjul-api" });
    if (path === "/push/key") return json(req, { key: VAPID_PUBLIC });
    if ((path === "/push/sub" || path === "/push/unsub" || path === "/push/test") && req.method === "POST") return pushApi(req, env, path);

    // 1) 카카오 로그인 시작
    if (path === "/kakao/login") {
      const ret = safeReturn(url.searchParams.get("return"));
      const state = crypto.randomUUID();
      await env.KV.put("s:" + state, ret, { expirationTtl: 600 });
      const k = new URL("https://kauth.kakao.com/oauth/authorize");
      k.searchParams.set("client_id", env.KAKAO_REST_KEY);
      k.searchParams.set("redirect_uri", REDIRECT);
      k.searchParams.set("response_type", "code");
      k.searchParams.set("state", state);
      return Response.redirect(k.toString(), 302);
    }

    // 2) 카카오에서 돌아옴
    if (path === "/kakao/callback") {
      const state = url.searchParams.get("state") || "";
      const ret = (await env.KV.get("s:" + state)) || APP_ORIGIN + "/";
      if (state) await env.KV.delete("s:" + state);
      const back = (frag) => Response.redirect(ret + "#" + frag, 302);
      const code = url.searchParams.get("code");
      if (!code) return back("login_error=" + encodeURIComponent(url.searchParams.get("error") || "cancel"));
      const form = new URLSearchParams({ grant_type: "authorization_code", client_id: env.KAKAO_REST_KEY, redirect_uri: REDIRECT, code });
      if (env.KAKAO_CLIENT_SECRET) form.set("client_secret", env.KAKAO_CLIENT_SECRET);
      const tr = await fetch("https://kauth.kakao.com/oauth/token", { method: "POST", headers: { "Content-Type": "application/x-www-form-urlencoded;charset=utf-8" }, body: form });
      const tk = await tr.json();
      if (!tk.access_token) {
        await env.KV.put("err:last", JSON.stringify({ at: Date.now(), step: "token", status: tr.status, body: tk }), { expirationTtl: 86400 * 7 });
        return back("login_error=token&code=" + encodeURIComponent(tk.error_code || tk.error || tr.status));
      }
      const mr = await fetch("https://kapi.kakao.com/v2/user/me", { headers: { Authorization: "Bearer " + tk.access_token } });
      const me = await mr.json();
      if (!me.id) {
        await env.KV.put("err:last", JSON.stringify({ at: Date.now(), step: "profile", status: mr.status, body: me }), { expirationTtl: 86400 * 7 });
        return back("login_error=profile&code=" + encodeURIComponent(me.code || mr.status));
      }
      const uid = String(me.id);
      const nick = (me.kakao_account && me.kakao_account.profile && me.kakao_account.profile.nickname) || (me.properties && me.properties.nickname) || "도반";
      return finishLogin(env, ret, uid, nick, "kakao");
    }

    // Google 로그인 시작
    if (path === "/google/login") {
      const ret = safeReturn(url.searchParams.get("return"));
      const state = crypto.randomUUID();
      await env.KV.put("s:" + state, ret, { expirationTtl: 600 });
      const g = new URL("https://accounts.google.com/o/oauth2/v2/auth");
      g.searchParams.set("client_id", env.GOOGLE_CLIENT_ID);
      g.searchParams.set("redirect_uri", G_REDIRECT);
      g.searchParams.set("response_type", "code");
      g.searchParams.set("scope", "openid profile");
      g.searchParams.set("state", state);
      g.searchParams.set("prompt", "select_account");
      return Response.redirect(g.toString(), 302);
    }

    // Google에서 돌아옴
    if (path === "/google/callback") {
      const state = url.searchParams.get("state") || "";
      const ret = (await env.KV.get("s:" + state)) || APP_ORIGIN + "/";
      if (state) await env.KV.delete("s:" + state);
      const back = (frag) => Response.redirect(ret + "#" + frag, 302);
      const code = url.searchParams.get("code");
      if (!code) return back("login_error=" + encodeURIComponent(url.searchParams.get("error") || "cancel"));
      const tr = await fetch("https://oauth2.googleapis.com/token", {
        method: "POST",
        headers: { "Content-Type": "application/x-www-form-urlencoded" },
        body: new URLSearchParams({ code, client_id: env.GOOGLE_CLIENT_ID, client_secret: env.GOOGLE_CLIENT_SECRET, redirect_uri: G_REDIRECT, grant_type: "authorization_code" }),
      });
      const tk = await tr.json();
      if (!tk.access_token) { await logErr(env, "g-token", tr.status, tk); return back("login_error=token&code=" + encodeURIComponent(tk.error || tr.status)); }
      const ur = await fetch("https://openidconnect.googleapis.com/v1/userinfo", { headers: { Authorization: "Bearer " + tk.access_token } });
      const me = await ur.json();
      if (!me.sub) { await logErr(env, "g-profile", ur.status, me); return back("login_error=profile"); }
      return finishLogin(env, ret, "g_" + me.sub, me.name || me.given_name || "도반", "google");
    }

    // 3) 로그인한 사용자 API
    if (path === "/me" || path === "/data" || path === "/account") {
      const user = await readToken(env, req);
      if (!user) return json(req, { error: "unauthorized" }, 401);

      if (path === "/me" && req.method === "GET") return json(req, { id: user.uid, nick: user.nick });

      if (path === "/data" && req.method === "GET") {
        const d = await env.KV.get("d:" + user.uid, "json");
        return json(req, d || { data: null, updatedAt: 0 });
      }
      if (path === "/data" && req.method === "PUT") {
        const txt = await req.text();
        if (txt.length > MAX_BYTES) return json(req, { error: "too_large" }, 413);
        let body;
        try { body = JSON.parse(txt); } catch (e) { return json(req, { error: "bad_json" }, 400); }
        if (!body || typeof body.data !== "object") return json(req, { error: "bad_body" }, 400);
        const rec = { data: body.data, updatedAt: Date.now() };
        await env.KV.put("d:" + user.uid, JSON.stringify(rec));
        return json(req, { ok: true, updatedAt: rec.updatedAt });
      }
      if (path === "/account" && req.method === "DELETE") {
        await env.KV.delete("d:" + user.uid);
        await env.KV.delete("u:" + user.uid);
        let unlinked = false;
        if (env.KAKAO_ADMIN_KEY && !user.uid.startsWith("g_")) {
          const r = await fetch("https://kapi.kakao.com/v1/user/unlink", {
            method: "POST",
            headers: { Authorization: "KakaoAK " + env.KAKAO_ADMIN_KEY, "Content-Type": "application/x-www-form-urlencoded" },
            body: new URLSearchParams({ target_id_type: "user_id", target_id: user.uid }),
          });
          unlinked = r.ok;
        }
        return json(req, { ok: true, unlinked });
      }
    }
    return json(req, { error: "not_found" }, 404);
  },
};

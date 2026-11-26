// Camioni WhatsApp verification server — zero dependencies, Node 18+.
// Endpoints:
//   GET  /api/health
//   POST /api/send-code   { "phone": "0561555300" }  -> sends a 4-digit code by WhatsApp
//   POST /api/verify-code { "phone": "0561555300", "code": "1234" } -> { "verified": true/false }
//   POST /api/driver-register (multipart/form-data)
//                      driver fields + document photos -> stored on disk and
//                      forwarded to the owner on WhatsApp
//   GET  /api/pending-registrations (header x-admin-key)
//   GET  /api/registrations/:id/file/:field (header x-admin-key)
//   POST /api/registrations/:id/imported (header x-admin-key)
//   GET  /                      -> static site for the request's Host
//   GET  /assets/<file>         -> static website files from public/assets/
//
// This server ALSO serves static sites, chosen by the request Host:
//   camioni.app (and camioni-whatsapp-server.fly.dev) -> the Camioni
//     website from public/ (copied from the website project, v204).
//   camioni.tech -> the driver registration page from public/driver/
//     (single self-contained file; it posts to /api/driver-register).
// Any GET request whose path does not start with /api/ is answered with the
// matching file in the Host's directory ("/" -> index.html, anything else
// -> 404). The /api/* endpoints work on both hosts.
//
// Configuration (environment variables, or a .env file next to this file):
//   WHATSAPP_TOKEN     permanent system-user token, permission whatsapp_business_messaging
//   PHONE_NUMBER_ID    Camioni WhatsApp Phone Number ID (1423215967538810)
//   PORT               default 8080
//   ALLOWED_ORIGINS    comma-separated origins allowed to call the API,
//                      default * (restrict this to the Camioni website when live)
//   MOCK_SEND          set to 1 only for local testing: no message is sent to Meta
//                      and the code is returned in the response so the flow can be tested.
//   WHATSAPP_TEMPLATE_NAME
//                      name of the approved WhatsApp authentication template, e.g.
//                      "camioni_verification_code". When set, codes are sent with
//                      that template, so they reach ANY customer — even a new one
//                      who never messaged the business. When empty, codes are sent
//                      as plain text, which only works inside an open 24-hour
//                      conversation window (the customer messaged first).
//                      The template itself must be created in WhatsApp Manager
//                      (category AUTHENTICATION, language ar, copy-code button,
//                      10-minute expiry) and approved by Meta before the server
//                      can use it. See README.md.
//   WHATSAPP_TEMPLATE_LANGUAGE
//                      language code of the template, default "ar".
//   ADMIN_KEY          secret for the admin endpoints (/api/pending-registrations,
//                      /api/registrations/:id/file/:field,
//                      /api/registrations/:id/imported), sent as the
//                      `x-admin-key` request header. When it is not set, the
//                      admin endpoints answer 503.
//   OWNER_WHATSAPP_NUMBER
//                      the owner's personal WhatsApp number, in international
//                      format without +, default 213561555300. New driver
//                      registrations are forwarded to this number (NOT the
//                      business number).
//
// The token is never logged and never sent to the browser. Codes live only in
// memory, expire after 10 minutes, and are deleted after a successful check.

const http = require("http");
const fs = require("fs");
const path = require("path");
const crypto = require("crypto");

// ---- tiny .env loader (KEY=VALUE lines, # comments) ----
try {
  const envPath = path.join(__dirname, ".env");
  if (fs.existsSync(envPath)) {
    for (const line of fs.readFileSync(envPath, "utf8").split("\n")) {
      const trimmed = line.trim();
      if (!trimmed || trimmed.startsWith("#")) continue;
      const eq = trimmed.indexOf("=");
      if (eq === -1) continue;
      const key = trimmed.slice(0, eq).trim();
      let value = trimmed.slice(eq + 1).trim();
      if ((value.startsWith('"') && value.endsWith('"')) || (value.startsWith("'") && value.endsWith("'"))) {
        value = value.slice(1, -1);
      }
      if (!(key in process.env)) process.env[key] = value;
    }
  }
} catch (err) {
  console.error("Could not read .env:", err.message);
}

const PORT = Number(process.env.PORT || 8080);
const WHATSAPP_TOKEN = (process.env.WHATSAPP_TOKEN || "").trim();
const PHONE_NUMBER_ID = (process.env.PHONE_NUMBER_ID || "1423215967538810").trim();
const WHATSAPP_TEMPLATE_NAME = (process.env.WHATSAPP_TEMPLATE_NAME || "").trim();
const WHATSAPP_TEMPLATE_LANGUAGE = (process.env.WHATSAPP_TEMPLATE_LANGUAGE || "ar").trim();
const MOCK_SEND = process.env.MOCK_SEND === "1";
const ADMIN_KEY = (process.env.ADMIN_KEY || "").trim();
const OWNER_WHATSAPP_NUMBER = (process.env.OWNER_WHATSAPP_NUMBER || "213561555300").trim();
const UPLOADS_DIR = path.join(__dirname, "uploads");
const PUBLIC_DIR = path.join(__dirname, "public"); // static Camioni website
const DRIVER_DIR = path.join(PUBLIC_DIR, "driver"); // driver registration page (camioni.tech)
const MAX_FILE_BYTES = 10 * 1024 * 1024; // 10MB per document
const MAX_TOTAL_UPLOAD_BYTES = 65 * 1024 * 1024; // 5 documents + fields
const DOC_FIELDS = ["licence_front", "licence_back", "grey_card", "insurance", "technical_inspection"];
const DOC_LABELS = {
  licence_front: "رخصة السياقة - الوجه الأمامي",
  licence_back: "رخصة السياقة - الوجه الخلفي",
  grey_card: "البطاقة الرمادية",
  insurance: "وثيقة التأمين",
  technical_inspection: "الفحص التقني",
};
const ALLOWED_ORIGINS = (process.env.ALLOWED_ORIGINS || "*")
  .split(",")
  .map((s) => s.trim())
  .filter(Boolean);

const CODE_TTL_MS = 10 * 60 * 1000; // 10 minutes
const RESEND_COOLDOWN_MS = 60 * 1000; // 1 minute between sends
const MAX_SENDS_PER_HOUR = 5;
const MAX_ATTEMPTS = 5;

// phone (213...) -> { code, expiresAt, attempts, lastSentAt, sentAtList }
const codes = new Map();

function normalizePhone(input) {
  if (typeof input !== "string") return null;
  let p = input.replace(/[\s\-()]/g, "");
  if (p.startsWith("+")) p = p.slice(1);
  if (p.startsWith("0") && p.length === 10) p = "213" + p.slice(1);
  if (!/^213[567]\d{8}$/.test(p)) return null;
  return p;
}

function readJsonBody(req) {
  return new Promise((resolve, reject) => {
    let raw = "";
    req.on("data", (chunk) => {
      raw += chunk;
      if (raw.length > 10000) {
        req.destroy();
        reject(new Error("body too large"));
      }
    });
    req.on("end", () => {
      if (!raw) return resolve({});
      try {
        resolve(JSON.parse(raw));
      } catch (e) {
        reject(new Error("invalid json"));
      }
    });
    req.on("error", reject);
  });
}

function sendJson(res, status, obj, origin) {
  const headers = { "Content-Type": "application/json" };
  if (origin) headers["Access-Control-Allow-Origin"] = origin;
  headers["Access-Control-Allow-Headers"] = "Content-Type, x-admin-key";
  headers["Access-Control-Allow-Methods"] = "GET, POST, OPTIONS";
  res.writeHead(status, headers);
  res.end(JSON.stringify(obj));
}

const STATIC_MIME = {
  ".html": "text/html; charset=utf-8",
  ".css": "text/css; charset=utf-8",
  ".js": "text/javascript; charset=utf-8",
  ".json": "application/json; charset=utf-8",
  ".webp": "image/webp",
  ".png": "image/png",
  ".jpg": "image/jpeg",
  ".jpeg": "image/jpeg",
  ".svg": "image/svg+xml",
  ".ico": "image/x-icon",
  ".woff": "font/woff",
  ".woff2": "font/woff2",
  ".ttf": "font/ttf",
};

// Serve one file from a static directory for a non-API GET request. "/"
// maps to <dir>/index.html. Returns true when the request was answered
// (file found or plain 404), false when the path escapes the directory
// (path traversal) so the caller can answer with its own 404.
function sendStatic(req, res, baseDir, pathname) {
  let rel;
  try {
    rel = pathname === "/" ? "index.html" : decodeURIComponent(pathname).replace(/^\/+/, "");
  } catch (e) {
    return false;
  }
  const filePath = path.resolve(baseDir, rel);
  if (filePath !== baseDir && !filePath.startsWith(baseDir + path.sep)) {
    return false;
  }
  fs.stat(filePath, (err, stat) => {
    // A directory serves its index.html (e.g. /driver/ -> public/driver/index.html).
    const target = !err && stat.isDirectory() ? path.join(filePath, "index.html") : filePath;
    fs.stat(target, (err2, stat2) => {
      if (err2 || !stat2.isFile()) {
        res.writeHead(404, { "Content-Type": "text/plain; charset=utf-8" });
        res.end("Not found");
        return;
      }
      const type = STATIC_MIME[path.extname(target).toLowerCase()] || "application/octet-stream";
      res.writeHead(200, { "Content-Type": type, "Content-Length": stat2.size });
      fs.createReadStream(target).pipe(res);
    });
  });
  return true;
}

function corsOrigin(req) {
  const origin = req.headers.origin;
  if (!origin) return "*";
  if (ALLOWED_ORIGINS.includes("*") || ALLOWED_ORIGINS.includes(origin)) return origin;
  return null;
}

async function sendWhatsAppText(to, text) {
  if (MOCK_SEND) {
    console.log("[MOCK] would send text to", to, ":", text);
    return { id: "mock-" + Date.now() };
  }
  const url = `https://graph.facebook.com/v21.0/${PHONE_NUMBER_ID}/messages`;
  const res = await fetch(url, {
    method: "POST",
    headers: {
      Authorization: "Bearer " + WHATSAPP_TOKEN,
      "Content-Type": "application/json",
    },
    body: JSON.stringify({
      messaging_product: "whatsapp",
      recipient_type: "individual",
      to,
      type: "text",
      text: { preview_url: false, body: text },
    }),
  });
  const data = await res.json().catch(() => ({}));
  if (!res.ok) {
    const err = new Error("WhatsApp send failed");
    err.status = res.status;
    err.meta = data;
    throw err;
  }
  return data.messages && data.messages[0];
}

// Send the code with the approved authentication template. The template's
// body text is fixed by Meta ("<code> is your verification code."); the code
// goes in twice: once as the body parameter and once as the copy-code button
// parameter, so the customer can tap "Copy code" and paste it on the website.
async function sendWhatsAppTemplate(to, code) {
  if (MOCK_SEND) {
    console.log("[MOCK] would send template", WHATSAPP_TEMPLATE_NAME, `(${WHATSAPP_TEMPLATE_LANGUAGE}) to`, to, "code", code);
    return { id: "mock-" + Date.now() };
  }
  const url = `https://graph.facebook.com/v21.0/${PHONE_NUMBER_ID}/messages`;
  const res = await fetch(url, {
    method: "POST",
    headers: {
      Authorization: "Bearer " + WHATSAPP_TOKEN,
      "Content-Type": "application/json",
    },
    body: JSON.stringify({
      messaging_product: "whatsapp",
      recipient_type: "individual",
      to,
      type: "template",
      template: {
        name: WHATSAPP_TEMPLATE_NAME,
        language: { code: WHATSAPP_TEMPLATE_LANGUAGE },
        components: [
          { type: "body", parameters: [{ type: "text", text: code }] },
          {
            type: "button",
            sub_type: "url",
            index: "0",
            parameters: [{ type: "text", text: code }],
          },
        ],
      },
    }),
  });
  const data = await res.json().catch(() => ({}));
  if (!res.ok) {
    const err = new Error("WhatsApp template send failed");
    err.status = res.status;
    err.meta = data;
    throw err;
  }
  return data.messages && data.messages[0];
}

// ---- driver registrations ----

// Minimal multipart/form-data parser (zero dependencies). Returns
// { fields: {name: string}, files: {name: {filename, mime, data: Buffer}} }.
function parseMultipartBuffer(buf, boundary) {
  const fields = {};
  const files = {};
  let idx = buf.indexOf(boundary, 0);
  while (idx !== -1) {
    let pos = idx + boundary.length;
    // "--" right after the boundary means the closing delimiter: done.
    if (buf[pos] === 0x2d && buf[pos + 1] === 0x2d) break;
    if (buf[pos] === 0x0d && buf[pos + 1] === 0x0a) pos += 2;
    const headerEnd = buf.indexOf("\r\n\r\n", pos);
    if (headerEnd === -1) break;
    const headers = buf.slice(pos, headerEnd).toString("utf8");
    const bodyStart = headerEnd + 4;
    const nextIdx = buf.indexOf(boundary, bodyStart);
    if (nextIdx === -1) break;
    let bodyEnd = nextIdx;
    if (buf[bodyEnd - 2] === 0x0d && buf[bodyEnd - 1] === 0x0a) bodyEnd -= 2;
    const body = buf.slice(bodyStart, bodyEnd);
    const disp = headers.match(/Content-Disposition:\s*form-data;\s*name="([^"]+)"(?:;\s*filename="([^"]*)")?/i);
    if (disp) {
      const name = disp[1];
      const filename = disp[2];
      if (filename !== undefined && filename !== "") {
        const typeMatch = headers.match(/Content-Type:\s*([^\r\n;]+)/i);
        const mime = (typeMatch ? typeMatch[1].trim() : "application/octet-stream").toLowerCase();
        files[name] = { filename, mime, data: body };
      } else {
        fields[name] = body.toString("utf8");
      }
    }
    idx = nextIdx;
  }
  return { fields, files };
}

function parseMultipart(req, maxBytes) {
  return new Promise((resolve, reject) => {
    const contentType = req.headers["content-type"] || "";
    const m = contentType.match(/multipart\/form-data;\s*boundary=(?:"([^"]+)"|([^;]+))/i);
    if (!m) return reject(new Error("not_multipart"));
    const boundary = Buffer.from("--" + (m[1] || m[2]).trim());
    const chunks = [];
    let total = 0;
    let tooBig = false;
    req.on("data", (chunk) => {
      total += chunk.length;
      if (total > maxBytes) {
        tooBig = true;
        req.destroy();
      } else {
        chunks.push(chunk);
      }
    });
    req.on("end", () => {
      if (tooBig) return reject(new Error("body_too_large"));
      try {
        resolve(parseMultipartBuffer(Buffer.concat(chunks), boundary));
      } catch (e) {
        reject(e);
      }
    });
    req.on("error", reject);
  });
}

// Upload a file to Meta so it can be sent as a WhatsApp media message.
// Returns the media object { id, ... }.
async function uploadWhatsAppMedia(data, mime, filename) {
  if (MOCK_SEND) {
    console.log("[MOCK] would upload media", filename, mime, data.length, "bytes");
    return { id: "mock-media-" + Date.now() };
  }
  const boundary = "----camioni" + crypto.randomBytes(8).toString("hex");
  const parts = [
    Buffer.from(`--${boundary}\r\nContent-Disposition: form-data; name="messaging_product"\r\n\r\nwhatsapp\r\n`),
    Buffer.from(`--${boundary}\r\nContent-Disposition: form-data; name="type"\r\n\r\n${mime}\r\n`),
    Buffer.from(`--${boundary}\r\nContent-Disposition: form-data; name="file"; filename="${filename}"\r\nContent-Type: ${mime}\r\n\r\n`),
    data,
    Buffer.from(`\r\n--${boundary}--\r\n`),
  ];
  const url = `https://graph.facebook.com/v21.0/${PHONE_NUMBER_ID}/media`;
  const res = await fetch(url, {
    method: "POST",
    headers: {
      Authorization: "Bearer " + WHATSAPP_TOKEN,
      "Content-Type": `multipart/form-data; boundary=${boundary}`,
    },
    body: Buffer.concat(parts),
  });
  const result = await res.json().catch(() => ({}));
  if (!res.ok) {
    const err = new Error("WhatsApp media upload failed");
    err.status = res.status;
    err.meta = result;
    throw err;
  }
  return result;
}

// Send one media message (image, or document for PDF) with a caption.
async function sendWhatsAppMedia(to, mediaId, mime, caption, filename) {
  if (MOCK_SEND) {
    console.log("[MOCK] would send media", mediaId, "to", to, "caption:", caption);
    return { id: "mock-" + Date.now() };
  }
  const isImage = mime.startsWith("image/");
  const type = isImage ? "image" : "document";
  const mediaObj = { id: mediaId, caption };
  if (!isImage) mediaObj.filename = filename;
  const url = `https://graph.facebook.com/v21.0/${PHONE_NUMBER_ID}/messages`;
  const res = await fetch(url, {
    method: "POST",
    headers: {
      Authorization: "Bearer " + WHATSAPP_TOKEN,
      "Content-Type": "application/json",
    },
    body: JSON.stringify({
      messaging_product: "whatsapp",
      recipient_type: "individual",
      to,
      type,
      [type]: mediaObj,
    }),
  });
  const data = await res.json().catch(() => ({}));
  if (!res.ok) {
    const err = new Error("WhatsApp media send failed");
    err.status = res.status;
    err.meta = data;
    throw err;
  }
  return data.messages && data.messages[0];
}

// Admin endpoints: "ok" | "unauthorized" | "not_configured" (no ADMIN_KEY set).
function checkAdminKey(req) {
  if (!ADMIN_KEY) return "not_configured";
  const given = req.headers["x-admin-key"];
  if (typeof given !== "string" || given.length !== ADMIN_KEY.length) return "unauthorized";
  try {
    return crypto.timingSafeEqual(Buffer.from(given), Buffer.from(ADMIN_KEY)) ? "ok" : "unauthorized";
  } catch {
    return "unauthorized";
  }
}

function readRegistration(id) {
  try {
    return JSON.parse(fs.readFileSync(path.join(UPLOADS_DIR, id, "registration.json"), "utf8"));
  } catch {
    return null;
  }
}

function listRegistrations() {
  if (!fs.existsSync(UPLOADS_DIR)) return [];
  const out = [];
  for (const name of fs.readdirSync(UPLOADS_DIR)) {
    if (!/^REG[0-9A-F]{8}$/.test(name)) continue;
    const meta = readRegistration(name);
    if (meta) out.push(meta);
  }
  out.sort((a, b) => (a.created_at < b.created_at ? 1 : -1));
  return out;
}

// Stored file name: <field>.<ext>. The extension comes from the original
// file name when it looks safe, otherwise from the mime type.
function safeExt(filename, mime) {
  const ext = path.extname(filename || "").toLowerCase();
  if (/^\.[a-z0-9]{2,5}$/.test(ext)) return ext;
  const byMime = {
    "image/jpeg": ".jpg",
    "image/png": ".png",
    "image/webp": ".webp",
    "image/gif": ".gif",
    "application/pdf": ".pdf",
  };
  return byMime[mime] || "";
}

function pruneOldSends(entry, now) {
  entry.sentAtList = entry.sentAtList.filter((t) => now - t < 60 * 60 * 1000);
}

const server = http.createServer(async (req, res) => {
  const origin = corsOrigin(req);
  if (req.method === "OPTIONS") {
    return sendJson(res, 204, {}, origin || "*");
  }
  const url = new URL(req.url, "http://localhost");

  if (req.method === "GET" && url.pathname === "/api/health") {
    return sendJson(res, 200, { ok: true, mock: MOCK_SEND }, origin || "*");
  }

  if (req.method === "POST" && url.pathname === "/api/send-code") {
    let body;
    try {
      body = await readJsonBody(req);
    } catch (e) {
      return sendJson(res, 400, { ok: false, error: "bad_request" }, origin || "*");
    }
    const phone = normalizePhone(body.phone);
    if (!phone) {
      return sendJson(res, 400, { ok: false, error: "invalid_phone" }, origin || "*");
    }
    const now = Date.now();
    const existing = codes.get(phone);
    if (existing) {
      pruneOldSends(existing, now);
      if (now - existing.lastSentAt < RESEND_COOLDOWN_MS) {
        return sendJson(res, 429, { ok: false, error: "cooldown", retryAfterSeconds: 60 }, origin || "*");
      }
      if (existing.sentAtList.length >= MAX_SENDS_PER_HOUR) {
        return sendJson(res, 429, { ok: false, error: "too_many_requests" }, origin || "*");
      }
    }
    if (!MOCK_SEND && !WHATSAPP_TOKEN) {
      return sendJson(res, 500, { ok: false, error: "server_not_configured" }, origin || "*");
    }
    const code = String(crypto.randomInt(1000, 10000));
    try {
      // With a template configured, the code reaches any customer, even a
      // new one. Without it, plain text only works inside an open 24-hour
      // conversation window.
      const sent = WHATSAPP_TEMPLATE_NAME
        ? await sendWhatsAppTemplate(phone, code)
        : await sendWhatsAppText(phone, `رمز التحقق الخاص بك في كاميوني هو ${code}`);
      const entry = existing || { sentAtList: [] };
      entry.code = code;
      entry.expiresAt = now + CODE_TTL_MS;
      entry.attempts = 0;
      entry.lastSentAt = now;
      entry.sentAtList.push(now);
      codes.set(phone, entry);
      console.log(`Code sent to ${phone}, message ${sent && sent.id ? sent.id : "?"}`);
      const out = { ok: true, expiresInSeconds: CODE_TTL_MS / 1000 };
      if (MOCK_SEND) out.mockCode = code; // testing only, never in production
      return sendJson(res, 200, out, origin || "*");
    } catch (e) {
      console.error("Send failed:", e.status || "", JSON.stringify(e.meta || e.message));
      return sendJson(res, 502, { ok: false, error: "whatsapp_send_failed" }, origin || "*");
    }
  }

  if (req.method === "POST" && url.pathname === "/api/verify-code") {
    let body;
    try {
      body = await readJsonBody(req);
    } catch (e) {
      return sendJson(res, 400, { ok: false, error: "bad_request" }, origin || "*");
    }
    const phone = normalizePhone(body.phone);
    const code = typeof body.code === "string" ? body.code.trim() : String(body.code || "").trim();
    if (!phone || !/^\d{4}$/.test(code)) {
      return sendJson(res, 400, { verified: false, error: "invalid_input" }, origin || "*");
    }
    const entry = codes.get(phone);
    if (!entry) {
      return sendJson(res, 200, { verified: false, error: "no_code" }, origin || "*");
    }
    if (Date.now() > entry.expiresAt) {
      codes.delete(phone);
      return sendJson(res, 200, { verified: false, error: "expired" }, origin || "*");
    }
    entry.attempts += 1;
    if (entry.attempts > MAX_ATTEMPTS) {
      codes.delete(phone);
      return sendJson(res, 200, { verified: false, error: "too_many_attempts" }, origin || "*");
    }
    const match =
      entry.code.length === code.length &&
      crypto.timingSafeEqual(Buffer.from(entry.code), Buffer.from(code));
    if (match) {
      codes.delete(phone);
      return sendJson(res, 200, { verified: true }, origin || "*");
    }
    return sendJson(res, 200, { verified: false, error: "wrong_code", attemptsLeft: MAX_ATTEMPTS - entry.attempts }, origin || "*");
  }

  // ---- driver registration (landing page) ----
  // POST /api/driver-register, multipart/form-data.
  // Text fields: first_name, last_name, phone (0[567] + 8 digits), vehicle_type,
  // wilaya, commune, optional referral_code.
  // Files (image or PDF, max 10MB each): licence_front, licence_back, grey_card,
  // insurance, technical_inspection.
  // Stored under ./uploads/<registrationId>/ with a registration.json next to
  // the files, then forwarded to the owner on WhatsApp (summary text + one
  // media message per document). A failed notification never fails the request.
  if (req.method === "POST" && url.pathname === "/api/driver-register") {
    let parsed;
    try {
      parsed = await parseMultipart(req, MAX_TOTAL_UPLOAD_BYTES);
    } catch (e) {
      if (e.message === "body_too_large") {
        return sendJson(res, 413, { ok: false, error: "body_too_large" }, origin || "*");
      }
      return sendJson(res, 400, { ok: false, error: "expected_multipart_form_data" }, origin || "*");
    }
    const f = parsed.fields;
    const required = ["first_name", "last_name", "phone", "vehicle_type", "wilaya", "commune"];
    const missing = required.filter((k) => !f[k] || !String(f[k]).trim());
    if (missing.length) {
      return sendJson(res, 400, { ok: false, error: "missing_fields", fields: missing }, origin || "*");
    }
    const phone = String(f.phone).replace(/[\s\-()]/g, "");
    if (!/^0[567]\d{8}$/.test(phone)) {
      return sendJson(res, 400, {
        ok: false,
        error: "invalid_phone",
        message: "الهاتف يجب أن يكون رقم هاتف جزائري يبدأ بـ 05 أو 06 أو 07 ويتكون من 10 أرقام",
      }, origin || "*");
    }
    const files = {};
    for (const field of DOC_FIELDS) {
      const file = parsed.files[field];
      if (!file) continue;
      if (!/^image\//.test(file.mime) && file.mime !== "application/pdf") {
        return sendJson(res, 400, { ok: false, error: "invalid_file_type", field, message: "الملف يجب أن يكون صورة أو PDF" }, origin || "*");
      }
      if (file.data.length > MAX_FILE_BYTES) {
        return sendJson(res, 400, { ok: false, error: "file_too_large", field, message: "حجم الملف يتجاوز 10MB" }, origin || "*");
      }
      files[field] = file;
    }
    const registrationId = "REG" + crypto.randomBytes(4).toString("hex").toUpperCase();
    const dir = path.join(UPLOADS_DIR, registrationId);
    fs.mkdirSync(dir, { recursive: true });
    const storedFiles = {};
    for (const [field, file] of Object.entries(files)) {
      const storedName = field + safeExt(file.filename, file.mime);
      fs.writeFileSync(path.join(dir, storedName), file.data);
      storedFiles[field] = {
        fileName: storedName,
        originalName: file.filename,
        mime: file.mime,
        size: file.data.length,
      };
    }
    const meta = {
      id: registrationId,
      first_name: String(f.first_name).trim(),
      last_name: String(f.last_name).trim(),
      phone,
      vehicle_type: String(f.vehicle_type).trim(),
      wilaya: String(f.wilaya).trim(),
      commune: String(f.commune).trim(),
      referral_code: (f.referral_code || "").trim() || null,
      files: storedFiles,
      created_at: new Date().toISOString(),
      status: "pending",
    };
    fs.writeFileSync(path.join(dir, "registration.json"), JSON.stringify(meta, null, 2));
    console.log(`Driver registration ${registrationId} stored (${Object.keys(storedFiles).length} files)`);

    const fullName = `${meta.first_name} ${meta.last_name}`;
    const summary =
      `تسجيل سائق جديد — كاميوني\n` +
      `الاسم: ${fullName}\n` +
      `الهاتف: ${meta.phone}\n` +
      `المركبة: ${meta.vehicle_type}\n` +
      `الولاية: ${meta.wilaya}\n` +
      `البلدية: ${meta.commune}` +
      (meta.referral_code ? `\nرمز الدعوة: ${meta.referral_code}` : "") +
      `\nرقم التسجيل: ${registrationId}`;
    let summarySent = false;
    try {
      await sendWhatsAppText(OWNER_WHATSAPP_NUMBER, summary);
      summarySent = true;
    } catch (e) {
      console.error(`Owner summary send failed for ${registrationId}:`, e.status || "", JSON.stringify(e.meta || e.message));
    }
    const failedDocuments = [];
    for (const [field, info] of Object.entries(storedFiles)) {
      try {
        const media = await uploadWhatsAppMedia(files[field].data, info.mime, info.fileName);
        await sendWhatsAppMedia(OWNER_WHATSAPP_NUMBER, media.id, info.mime, `${DOC_LABELS[field]} - ${fullName}`, info.fileName);
      } catch (e) {
        console.error(`Owner media send failed for ${registrationId}/${field}:`, e.status || "", JSON.stringify(e.meta || e.message));
        failedDocuments.push(field);
      }
    }
    return sendJson(res, 200, {
      ok: true,
      registrationId,
      files: Object.keys(storedFiles),
      failedDocuments,
      summarySent,
    }, origin || "*");
  }

  // ---- admin endpoints (header x-admin-key; 503 when ADMIN_KEY is not set) ----
  if (req.method === "GET" && url.pathname === "/api/pending-registrations") {
    const auth = checkAdminKey(req);
    if (auth === "not_configured") {
      return sendJson(res, 503, { ok: false, error: "admin_key_not_configured" }, origin || "*");
    }
    if (auth !== "ok") {
      return sendJson(res, 401, { ok: false, error: "unauthorized" }, origin || "*");
    }
    const regs = listRegistrations()
      .filter((r) => r.status === "pending")
      .map((r) => ({
        id: r.id,
        first_name: r.first_name,
        last_name: r.last_name,
        phone: r.phone,
        vehicle_type: r.vehicle_type,
        wilaya: r.wilaya,
        commune: r.commune,
        referral_code: r.referral_code,
        created_at: r.created_at,
        status: r.status,
        files: Object.fromEntries(
          Object.entries(r.files || {}).map(([field, info]) => [
            field,
            { ...info, download: `/api/registrations/${r.id}/file/${field}` },
          ])
        ),
      }));
    return sendJson(res, 200, { ok: true, count: regs.length, registrations: regs }, origin || "*");
  }

  const fileMatch = url.pathname.match(/^\/api\/registrations\/(REG[0-9A-F]{8})\/file\/([a-z_]+)$/);
  if (req.method === "GET" && fileMatch) {
    const auth = checkAdminKey(req);
    if (auth === "not_configured") {
      return sendJson(res, 503, { ok: false, error: "admin_key_not_configured" }, origin || "*");
    }
    if (auth !== "ok") {
      return sendJson(res, 401, { ok: false, error: "unauthorized" }, origin || "*");
    }
    const meta = readRegistration(fileMatch[1]);
    const info = meta && (meta.files || {})[fileMatch[2]];
    if (!info) {
      return sendJson(res, 404, { ok: false, error: "file_not_found" }, origin || "*");
    }
    const filePath = path.join(UPLOADS_DIR, fileMatch[1], info.fileName);
    if (!filePath.startsWith(path.join(UPLOADS_DIR, fileMatch[1]) + path.sep) || !fs.existsSync(filePath)) {
      return sendJson(res, 404, { ok: false, error: "file_not_found" }, origin || "*");
    }
    const data = fs.readFileSync(filePath);
    const headers = {
      "Content-Type": info.mime,
      "Content-Disposition": `inline; filename="${info.fileName}"`,
      "Content-Length": data.length,
    };
    if (origin) headers["Access-Control-Allow-Origin"] = origin;
    res.writeHead(200, headers);
    return res.end(data);
  }

  const importedMatch = url.pathname.match(/^\/api\/registrations\/(REG[0-9A-F]{8})\/imported$/);
  if (req.method === "POST" && importedMatch) {
    const auth = checkAdminKey(req);
    if (auth === "not_configured") {
      return sendJson(res, 503, { ok: false, error: "admin_key_not_configured" }, origin || "*");
    }
    if (auth !== "ok") {
      return sendJson(res, 401, { ok: false, error: "unauthorized" }, origin || "*");
    }
    const meta = readRegistration(importedMatch[1]);
    if (!meta) {
      return sendJson(res, 404, { ok: false, error: "registration_not_found" }, origin || "*");
    }
    meta.status = "imported";
    fs.writeFileSync(
      path.join(UPLOADS_DIR, importedMatch[1], "registration.json"),
      JSON.stringify(meta, null, 2)
    );
    return sendJson(res, 200, { ok: true, registrationId: importedMatch[1], status: "imported" }, origin || "*");
  }

  // Static sites, chosen by Host: camioni.tech serves the driver
  // registration page (public/driver/); every other host serves the
  // website (public/). /api/* works on both hosts.
  if (req.method === "GET" && !url.pathname.startsWith("/api/")) {
    const host = String(req.headers.host || "").toLowerCase().split(":")[0];
    const baseDir = host === "camioni.tech" || host.endsWith(".camioni.tech") ? DRIVER_DIR : PUBLIC_DIR;
    if (sendStatic(req, res, baseDir, url.pathname)) return;
  }

  return sendJson(res, 404, { ok: false, error: "not_found" }, origin || "*");
});

// Drop expired codes every 5 minutes so memory does not grow.
setInterval(() => {
  const now = Date.now();
  for (const [phone, entry] of codes) {
    if (now > entry.expiresAt) codes.delete(phone);
  }
}, 5 * 60 * 1000).unref();

server.listen(PORT, "0.0.0.0", () => {
  console.log(`Camioni WhatsApp verification server on port ${PORT} (mock=${MOCK_SEND})`);
});

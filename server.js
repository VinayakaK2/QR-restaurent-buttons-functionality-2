import express from "express";
import fs from "fs/promises";
import path from "path";
import dotenv from "dotenv";
import cookieParser from "cookie-parser";
import bcrypt from "bcryptjs";
import helmet from "helmet";
import rateLimit from "express-rate-limit";
import { Server as IOServer } from "socket.io";
import http from "http";
import nodemailer from "nodemailer";
import QRCode from "qrcode";
import csurf from "csurf";
import { v4 as uuidv4 } from "uuid";
import { MongoClient } from "mongodb";

dotenv.config();
const PORT = process.env.PORT || 3000;
const DATA_FILE = path.resolve("./data.json");
const PUBLIC_DIR = path.resolve("./"); // Serve current folder

// ---------- Location Config (edit these) ----------
// Set your restaurant latitude/longitude here. Radius is set to 10 meters.
// Environment variables (RESTAURANT_LAT/RESTAURANT_LNG/RESTAURANT_RADIUS_METERS) still override if present.
const CONFIG_LOCATION = {
  lat: Number(process.env.RESTAURANT_LAT) || 14.478144241010149,
  lng: Number(process.env.RESTAURANT_LNG) || 75.88522999510667,
  radiusMeters: Number(process.env.RESTAURANT_RADIUS_METERS || process.env.PROXIMITY_RADIUS_METERS) || 10
};

const ADMIN_COOKIE_NAME = "sessionUser";
let adminUsernameCache = process.env.ADMIN_USERNAME || "admin";
const SESSION_TTL_MS = 3 * 60 * 60 * 1000;

// Log loaded location config at startup
console.log("[Config] Restaurant Location:", CONFIG_LOCATION);

const app = express();
const server = http.createServer(app);
const io = new IOServer(server, { cors: { origin: true, credentials: true } });

function getAdminCookie(req) {
  return req?.cookies?.[ADMIN_COOKIE_NAME] || null;
}

function isAdminRequest(req) {
  return Boolean(getAdminCookie(req) && getAdminCookie(req) === adminUsernameCache);
}

function setAdminSession(res, username) {
  if (!username) return;
  res.cookie(ADMIN_COOKIE_NAME, username, { httpOnly: true, sameSite: "lax", secure: false, path: "/" });
}

function clearAdminSession(res) {
  res.clearCookie(ADMIN_COOKIE_NAME);
}

app.use(helmet({
  contentSecurityPolicy: {
    useDefaults: true,
    directives: {
      "default-src": ["'self'"],
      "script-src": [
        "'self'",
        "'unsafe-inline'",
        "https://cdnjs.cloudflare.com",
        "https://cdn.jsdelivr.net",
        "https://cdn.socket.io",
        "https://fonts.googleapis.com",
        "https://fonts.gstatic.com"
      ],
      "script-src-elem": [
        "'self'",
        "'unsafe-inline'",
        "https://cdnjs.cloudflare.com",
        "https://cdn.jsdelivr.net",
        "https://cdn.socket.io",
        "https://fonts.googleapis.com",
        "https://fonts.gstatic.com"
      ],
      // Allow inline event handlers like onclick for existing HTML pages
      "script-src-attr": ["'unsafe-inline'"],
      "style-src": [
        "'self'",
        "'unsafe-inline'",
        "https://fonts.googleapis.com",
        "https://cdnjs.cloudflare.com"
      ],
      "img-src": ["'self'", "data:", "https://images.unsplash.com"],
      "connect-src": ["'self'", "https://cdnjs.cloudflare.com", "https://cdn.jsdelivr.net"],
      "font-src": ["'self'", "https://fonts.gstatic.com", "https://cdnjs.cloudflare.com", "data:"],
      "frame-ancestors": ["'self'"]
    }
  }
}));
app.use(express.json());
app.use(cookieParser());
// Protect selected admin pages while keeping the rest of the site public
const PROTECTED_PAGES = new Set([
  "/admin.html",
  "/analytics.html",
  "/bill.html",
  "/categories.html",
  "/menumng.html",
  "/orders.html",
  "/qrgenerator.html",
  "/settings.html"
]);

function ensureAdminPage(req, res, next) {
  if (isAdminRequest(req)) {
    return next();
  }
  return res.redirect("/login.html");
}

// Intercept requests to protected HTML pages and verify admin
app.get(Array.from(PROTECTED_PAGES), ensureAdminPage, (req, res) => {
  res.sendFile(path.join(PUBLIC_DIR, req.path));
});

// Serve other static assets as usual
app.use(express.static(PUBLIC_DIR));
// Protect admin pages
app.use("/secure", auth, express.static(path.join(PUBLIC_DIR, "secure")));
app.use("/secure", (req, res) => {
  res.redirect("/login.html");
});

const csrfProtection = csurf({ cookie: true });

const limiter = rateLimit({
  windowMs: 60 * 1000,
  max: 20,
  message: { ok: false, message: "Too many requests" }
});
app.use("/api/orders/create", limiter);

// ---------- Utility ----------
// ---------- Storage Layer (MongoDB with file fallback) ----------
let mongoClient = null;
let mongoDb = null;

async function connectMongoIfConfigured() {
  const uri = process.env.MONGODB_URI;
  const dbName = process.env.MONGODB_DB || "qrrp";
  if (!uri) return null;
  if (mongoDb) return mongoDb;
  mongoClient = new MongoClient(uri, { serverSelectionTimeoutMS: 5000 });
  await mongoClient.connect();
  mongoDb = mongoClient.db(dbName);
  return mongoDb;
}

async function readData() {
  try {
    const raw = await fs.readFile(DATA_FILE, "utf8");
    return JSON.parse(raw);
  } catch (err) {
    if (err.code === 'ENOENT') {  // Handle if file not exist
      const defaultData = {
        admin: { username: process.env.ADMIN_USERNAME || 'admin' },
        tables: [],
        orders: []
      };
      await writeData(defaultData);  // Create file with default
      return defaultData;
    }
    throw err;  // Other errors
  }
}
async function writeData(data) {
  await fs.writeFile(DATA_FILE, JSON.stringify(data, null, 2), "utf8");
}

function sanitizeSessionData(data) {
  if (data === null || data === undefined) return null;
  if (typeof data === "object") {
    try {
      return JSON.parse(JSON.stringify(data));
    } catch {
      return null;
    }
  }
  if (typeof data === "string" || typeof data === "number" || typeof data === "boolean") {
    return data;
  }
  return null;
}

function nextSessionExpiryISO() {
  return new Date(Date.now() + SESSION_TTL_MS).toISOString();
}

function normalizeSessionRecord(session) {
  if (!session) return null;
  return {
    userId: session.userId,
    tableId: session.tableId,
    userData: session.userData ?? null,
    createdAt: session.createdAt,
    updatedAt: session.updatedAt,
    expiresAt: session.expiresAt instanceof Date ? session.expiresAt.toISOString() : session.expiresAt
  };
}

async function pruneExpiredSessionsFile(data) {
  if (!Array.isArray(data.sessions)) data.sessions = [];
  const now = Date.now();
  const active = data.sessions.filter(s => {
    const expiresAt = new Date(s.expiresAt || 0).getTime();
    return expiresAt > now;
  });
  if (active.length !== data.sessions.length) {
    data.sessions = active;
    await writeData(data);
  }
  return data.sessions;
}

async function loadSession(userId) {
  if (!userId) return null;
  if (mongoDb) {
    const session = await mongoDb.collection("sessions").findOne({ userId });
    if (!session) return null;
    if (session.expiresAt && session.expiresAt.getTime() <= Date.now()) {
      await mongoDb.collection("sessions").deleteOne({ userId });
      return null;
    }
    return normalizeSessionRecord(session);
  }
  const data = await readData();
  const sessions = await pruneExpiredSessionsFile(data);
  return sessions.find(s => s.userId === userId) || null;
}

async function persistSession(session) {
  const record = {
    userId: session.userId,
    tableId: session.tableId,
    userData: sanitizeSessionData(session.userData),
    createdAt: session.createdAt,
    updatedAt: session.updatedAt,
    expiresAt: session.expiresAt
  };
  if (mongoDb) {
    const expiresAtDate = new Date(record.expiresAt);
    await mongoDb.collection("sessions").updateOne(
      { userId: record.userId },
      {
        $setOnInsert: { createdAt: record.createdAt },
        $set: {
          tableId: record.tableId,
          userData: record.userData ?? null,
          updatedAt: record.updatedAt,
          expiresAt: expiresAtDate
        }
      },
      { upsert: true }
    );
    return { ...record, expiresAt: expiresAtDate.toISOString() };
  }
  const data = await readData();
  if (!Array.isArray(data.sessions)) data.sessions = [];
  const idx = data.sessions.findIndex(s => s.userId === record.userId);
  if (idx >= 0) {
    record.createdAt = data.sessions[idx].createdAt || record.createdAt;
    data.sessions[idx] = record;
  } else {
    data.sessions.push(record);
  }
  await writeData(data);
  return record;
}

async function upsertSession({ userId, tableId, userData }) {
  const existing = await loadSession(userId);
  const nowIso = new Date().toISOString();
  if (existing) {
    const updated = {
      ...existing,
      tableId,
      userData: userData !== undefined ? sanitizeSessionData(userData) : existing.userData,
      updatedAt: nowIso,
      expiresAt: nextSessionExpiryISO()
    };
    return persistSession(updated);
  }
  const created = {
    userId,
    tableId,
    userData: sanitizeSessionData(userData),
    createdAt: nowIso,
    updatedAt: nowIso,
    expiresAt: nextSessionExpiryISO()
  };
  return persistSession(created);
}

function sanitizeTableResponse(table) {
  if (!table) return null;
  return {
    id: table.id,
    number: table.number ?? null,
    name: table.name ?? null,
    capacity: table.capacity ?? null,
    status: table.status ?? "available",
    qrUrl: table.qrUrl || "",
    qrGeneratedAt: table.qrGeneratedAt || null,
    activeOrderId: table.activeOrderId ?? null,
    createdAt: table.createdAt,
    updatedAt: table.updatedAt
  };
}

function buildTableRecord(input, { existing } = {}) {
  const nowIso = new Date().toISOString();
  const base = existing ? { ...existing } : {};
  const record = {
    ...base,
    id: existing?.id || input.id || uuidv4(),
    number: input.number !== undefined ? Number(input.number) : (existing?.number ?? null),
    name: input.name || existing?.name || (input.number ? `Table ${input.number}` : existing?.name || null),
    capacity: input.capacity !== undefined ? Number(input.capacity) : (existing?.capacity ?? 4),
    status: input.status || existing?.status || "available",
    activeOrderId: existing?.activeOrderId ?? null,
    qrUrl: input.qrUrl !== undefined ? input.qrUrl : (existing?.qrUrl || ""),
    qrGeneratedAt: input.qrGeneratedAt !== undefined ? input.qrGeneratedAt : (existing?.qrGeneratedAt || null),
    pinHash: existing?.pinHash || input.pinHash || null,
    createdAt: existing?.createdAt || nowIso,
    updatedAt: nowIso
  };
  return record;
}

async function listTables() {
  if (mongoDb) {
    const docs = await mongoDb.collection("tables").find({}).sort({ number: 1 }).toArray();
    return docs.map(doc => ({
      ...doc,
      id: doc.id || (doc._id ? String(doc._id) : undefined)
    }));
  }
  const data = await readData();
  return Array.isArray(data.tables) ? data.tables : [];
}

async function findTableById(tableId) {
  if (!tableId) return null;
  if (mongoDb) {
    const doc = await mongoDb.collection("tables").findOne({ id: String(tableId) });
    if (doc) return { ...doc, id: doc.id || (doc._id ? String(doc._id) : undefined) };
    return null;
  }
  const data = await readData();
  return (data.tables || []).find(t => String(t.id) === String(tableId)) || null;
}

async function findTableByNumber(tableNumber) {
  if (tableNumber === undefined || tableNumber === null) return null;
  const number = Number(tableNumber);
  if (Number.isNaN(number)) return null;
  if (mongoDb) {
    const doc = await mongoDb.collection("tables").findOne({ number });
    if (doc) return { ...doc, id: doc.id || (doc._id ? String(doc._id) : undefined) };
    return null;
  }
  const data = await readData();
  return (data.tables || []).find(t => Number(t.number) === number) || null;
}

async function saveTableRecord(record) {
  if (!record) return null;
  if (mongoDb) {
    const collection = mongoDb.collection("tables");
    await collection.updateOne(
      { id: record.id },
      { $set: { ...record } },
      { upsert: true }
    );
    return record;
  }
  const data = await readData();
  if (!Array.isArray(data.tables)) data.tables = [];
  const idx = data.tables.findIndex(t => String(t.id) === String(record.id));
  if (idx >= 0) {
    data.tables[idx] = record;
  } else {
    data.tables.push(record);
  }
  await writeData(data);
  return record;
}

async function deleteTableById(tableId) {
  if (!tableId) return false;
  if (mongoDb) {
    const res = await mongoDb.collection("tables").deleteOne({ id: String(tableId) });
    return res.deletedCount > 0;
  }
  const data = await readData();
  const before = data.tables?.length || 0;
  data.tables = (data.tables || []).filter(t => String(t.id) !== String(tableId));
  const after = data.tables.length;
  await writeData(data);
  return after < before;
}
function dist(lat1, lon1, lat2, lon2) {
  const R = 6371e3;
  const φ1 = lat1 * Math.PI/180, φ2 = lat2 * Math.PI/180;
  const Δφ = (lat2 - lat1) * Math.PI/180, Δλ = (lon2 - lon1) * Math.PI/180;
  const a = Math.sin(Δφ/2)**2 + Math.cos(φ1)*Math.cos(φ2)*Math.sin(Δλ/2)**2;
  return R * 2 * Math.atan2(Math.sqrt(a), Math.sqrt(1-a));
}

// ---------- Mail ----------
const mailer = nodemailer.createTransport({
  host: process.env.SMTP_HOST,
  port: Number(process.env.SMTP_PORT),
  secure: false,
  auth: { user: process.env.SMTP_USER, pass: process.env.SMTP_PASS }
});
async function sendMail(order) {
  if (!process.env.NOTIFY_EMAIL) return;
  await mailer.sendMail({
    from: process.env.SMTP_USER,
    to: process.env.NOTIFY_EMAIL,
    subject: `New order #${order.id} - Table ${order.tableId}`,
    text: order.items.map(i => `${i.name} x${i.qty}`).join("\n")
  }).catch(console.warn);
}

// ---------- Auth ----------
function auth(req, res, next) {
  if (!isAdminRequest(req)) {
    return res.status(401).json({ ok: false });
  }
  req.user = { username: adminUsernameCache };
  next();
}

// ---------- Init ----------
async function init() {
  // Try Mongo connect
  try {
    await connectMongoIfConfigured();
  } catch (e) {
    console.warn("MongoDB connection failed, using file storage:", e.message);
  }

  if (mongoDb) {
    try {
      const sessionCol = mongoDb.collection("sessions");
      await sessionCol.createIndex({ userId: 1 }, { unique: true });
      await sessionCol.createIndex({ expiresAt: 1 }, { expireAfterSeconds: 0 });
    } catch (err) {
      console.warn("Session index creation failed:", err.message);
    }
    // Ensure admin exists and migrate from file once
    const adminCol = mongoDb.collection("admin");
    const tablesCol = mongoDb.collection("tables");
    const ordersCol = mongoDb.collection("orders");

    let adminDoc = await adminCol.findOne({ _id: "admin" });
    if (!adminDoc) {
      // Try migrate from file, else create default
      let d = null;
      try { d = await readData(); } catch {}
      const username = d?.admin?.username || process.env.ADMIN_USERNAME || 'admin';
      const passwordHash = d?.admin?.passwordHash || bcrypt.hashSync(process.env.ADMIN_PASSWORD || 'admin123', 10);
      await adminCol.updateOne(
        { _id: "admin" },
        { $set: { username, passwordHash } },
        { upsert: true }
      );
      adminDoc = { _id: "admin", username, passwordHash };
      // migrate tables
      if (Array.isArray(d?.tables)) {
        for (const t of d.tables) {
          const pinHash = t.pinHash || bcrypt.hashSync(t.pinPlain || "1234", 10);
          await tablesCol.updateOne(
            { id: String(t.id) },
            { $set: { id: String(t.id), pinHash } },
            { upsert: true }
          );
        }
      }
      // migrate orders
      if (Array.isArray(d?.orders)) {
        if ((await ordersCol.estimatedDocumentCount()) === 0) {
          await ordersCol.insertMany(d.orders.map(o => ({ ...o, _id: o.id })));
        }
      }
    }
    if (adminDoc?.username) {
      adminUsernameCache = adminDoc.username;
    }
  } else {
    // File storage initialization
    const d = await readData();
    if (!d.admin) {  // Create admin if missing
      d.admin = { username: process.env.ADMIN_USERNAME || 'admin' };
    }
    if (!d.admin.passwordHash) {
      d.admin.passwordHash = bcrypt.hashSync(process.env.ADMIN_PASSWORD || 'admin123', 10);
    }
    for (let t of d.tables) {
      if (!t.pinHash) {
        t.pinHash = bcrypt.hashSync(t.pinPlain || "1234", 10);
        delete t.pinPlain;  // Remove plain pin for security
      }
    }
    if (!Array.isArray(d.sessions)) {
      d.sessions = [];
    }
    await writeData(d);
    if (d.admin?.username) {
      adminUsernameCache = d.admin.username;
    }
  }
}
await init();

// ---------- Simple distance check endpoint ----------
// Uses fixed restaurant location (same as CONFIG_LOCATION) and a 100m radius.
app.post("/check-distance", (req, res) => {
  const { userLat, userLong } = req.body || {};

  const lat = Number(userLat);
  const lng = Number(userLong);

  if (!Number.isFinite(lat) || !Number.isFinite(lng)) {
    return res.status(400).json({ allowed: false, message: "Invalid coordinates" });
  }

  const distance = dist(
    CONFIG_LOCATION.lat,
    CONFIG_LOCATION.lng,
    lat,
    lng
  );

  console.log("[Simple Distance Check]", {
    userLat: lat,
    userLong: lng,
    distance: Math.round(distance)
  });

  const allowed = distance <= CONFIG_LOCATION.radiusMeters;
  res.json({ allowed, distance, radius: CONFIG_LOCATION.radiusMeters });
});

// ---------- API ----------
app.post("/api/auth/login", async (req, res) => {
  const { username, password } = req.body;
  if (mongoDb) {
    const adm = await mongoDb.collection("admin").findOne({ _id: "admin" });
    if (!adm || username !== adm.username) return res.status(401).json({ ok: false, msg: 'Invalid username' });
    if (!bcrypt.compareSync(password, adm.passwordHash))
      return res.status(401).json({ ok: false, msg: 'Invalid password' });
    adminUsernameCache = adm.username || adminUsernameCache;
  } else {
    const d = await readData();
    if (username !== d.admin.username) return res.status(401).json({ ok: false, msg: 'Invalid username' });
    if (!bcrypt.compareSync(password, d.admin.passwordHash))
      return res.status(401).json({ ok: false, msg: 'Invalid password' });
    adminUsernameCache = d.admin.username || adminUsernameCache;
  }
  setAdminSession(res, username);
  res.json({ ok: true });
});

app.get("/api/auth/me", (req, res) => {
  if (!isAdminRequest(req)) {
    return res.status(401).json({ ok: false, msg: "Invalid or expired session" });
  }
  res.json({ ok: true, user: { username: adminUsernameCache } });
});

app.post("/api/auth/logout", (req, res) => {
  clearAdminSession(res);
  res.json({ ok: true });
});

app.post("/api/admin/generate-qr", auth, async (req, res) => {
  try {
    const { tableId, baseUrl } = req.body || {};
    if (!tableId) return res.status(400).json({ ok: false, message: "tableId required" });
    const tableRecord = await findTableById(tableId);
    if (!tableRecord) {
      return res.status(404).json({ ok: false, message: "Table not found" });
    }
    const fallbackBase = `${req.protocol}://${req.get("host")}/entry.html`;
    const normalizedBaseUrl = String(baseUrl || fallbackBase).trim();
    const finalUrl = `${normalizedBaseUrl}${normalizedBaseUrl.includes("?") ? "&" : "?"}tableId=${encodeURIComponent(String(tableRecord.id))}${tableRecord.number !== undefined && tableRecord.number !== null ? `&tableNumber=${encodeURIComponent(String(tableRecord.number))}` : ""}`;
    let qrImageData = null;
    try {
      qrImageData = await QRCode.toDataURL(finalUrl, { errorCorrectionLevel: 'L', margin: 0, width: 180 });
    } catch (e) { console.warn("QR generation failed", e.message); }
    const updated = buildTableRecord({
      qrUrl: finalUrl,
      qrGeneratedAt: new Date().toISOString()
    }, { existing: tableRecord });
    await saveTableRecord(updated);
    // Emit table update event
    const allTables = await listTables();
    io.emit("tables:update", allTables.map(sanitizeTableResponse));
    res.json({ ok: true, qrUrl: finalUrl, qrImageData, table: sanitizeTableResponse(updated) });
  } catch (err) {
    console.error("Admin QR generation failed", err);
    res.status(500).json({ ok: false, message: "QR generation error" });
  }
});

app.get("/api/tables", auth, async (req, res) => {
  try {
    const tables = await listTables();
    res.json({ ok: true, tables: tables.map(sanitizeTableResponse) });
  } catch (err) {
    console.error("Tables fetch failed", err);
    res.status(500).json({ ok: false, message: "Failed to load tables" });
  }
});

app.post("/api/tables", auth, async (req, res) => {
  try {
    const { number, capacity, name, status, pin } = req.body || {};
    const tableNumber = Number(number);
    if (!Number.isFinite(tableNumber) || tableNumber <= 0) {
      return res.status(400).json({ ok: false, message: "Valid table number required" });
    }
    const existingNumber = await findTableByNumber(tableNumber);
    if (existingNumber) {
      return res.status(409).json({ ok: false, message: "Table number already exists" });
    }
    const hashSource = typeof pin === "string" && pin.trim() ? pin.trim() : "1234";
    const record = buildTableRecord({
      number: tableNumber,
      capacity: Number(capacity) || 4,
      name: name || `Table ${tableNumber}`,
      status: status || "available",
      pinHash: bcrypt.hashSync(hashSource, 10)
    });
    const saved = await saveTableRecord(record);
    // Emit table update event
    const allTables = await listTables();
    io.emit("tables:update", allTables.map(sanitizeTableResponse));
    res.json({ ok: true, table: sanitizeTableResponse(saved) });
  } catch (err) {
    console.error("Table create failed", err);
    res.status(500).json({ ok: false, message: "Failed to create table" });
  }
});

app.patch("/api/tables/:id", auth, async (req, res) => {
  try {
    const tableId = req.params.id;
    const existing = await findTableById(tableId);
    if (!existing) {
      return res.status(404).json({ ok: false, message: "Table not found" });
    }
    const updates = { ...req.body };
    if (updates.number !== undefined) {
      const newNumber = Number(updates.number);
      if (!Number.isFinite(newNumber) || newNumber <= 0) {
        return res.status(400).json({ ok: false, message: "Invalid table number" });
      }
      const conflict = await findTableByNumber(newNumber);
      if (conflict && String(conflict.id) !== String(tableId)) {
        return res.status(409).json({ ok: false, message: "Table number already exists" });
      }
      updates.number = newNumber;
    }
    if (updates.capacity !== undefined) {
      updates.capacity = Number(updates.capacity) || existing.capacity || 4;
    }
    if (typeof updates.pin === "string" && updates.pin.trim()) {
      updates.pinHash = bcrypt.hashSync(updates.pin.trim(), 10);
    }
    const record = buildTableRecord(updates, { existing });
    const saved = await saveTableRecord(record);
    // Emit table update event
    const allTables = await listTables();
    io.emit("tables:update", allTables.map(sanitizeTableResponse));
    res.json({ ok: true, table: sanitizeTableResponse(saved) });
  } catch (err) {
    console.error("Table update failed", err);
    res.status(500).json({ ok: false, message: "Failed to update table" });
  }
});

app.delete("/api/tables/:id", auth, async (req, res) => {
  try {
    const tableId = req.params.id;
    const removed = await deleteTableById(tableId);
    if (!removed) {
      return res.status(404).json({ ok: false, message: "Table not found" });
    }
    // Emit table update event
    const allTables = await listTables();
    io.emit("tables:update", allTables.map(sanitizeTableResponse));
    res.json({ ok: true });
  } catch (err) {
    console.error("Table delete failed", err);
    res.status(500).json({ ok: false, message: "Failed to delete table" });
  }
});

// Frontend QR generator endpoint used by qrgenerator.html
app.post("/api/qr/generate", auth, async (req, res) => {
  try {
    const { tableId, table: legacyTableNumber, baseUrl, autoCreate } = req.body || {};
    const normalizedBaseUrl = String(baseUrl || "").trim();
    if (!tableId && (legacyTableNumber === undefined || legacyTableNumber === null)) {
      return res.status(400).json({ ok: false, message: "tableId or table number required" });
    }
    if (!normalizedBaseUrl) return res.status(400).json({ ok: false, message: "baseUrl required" });

    let tableRecord = null;
    if (tableId) {
      tableRecord = await findTableById(tableId);
    } else if (legacyTableNumber !== undefined && legacyTableNumber !== null) {
      tableRecord = await findTableByNumber(legacyTableNumber);
    }

    if (!tableRecord && autoCreate && legacyTableNumber !== undefined) {
      const created = buildTableRecord({
        number: Number(legacyTableNumber),
        capacity: 4,
        name: `Table ${legacyTableNumber}`,
        status: "available",
        pinHash: bcrypt.hashSync("1234", 10)
      });
      tableRecord = await saveTableRecord(created);
    }

    if (!tableRecord) {
      return res.status(404).json({ ok: false, message: "Table not found" });
    }

    const finalUrl = `${normalizedBaseUrl}${normalizedBaseUrl.includes("?") ? "&" : "?"}tableId=${encodeURIComponent(String(tableRecord.id))}${tableRecord.number !== undefined && tableRecord.number !== null ? `&tableNumber=${encodeURIComponent(String(tableRecord.number))}` : ""}`;

    let qrImageData = null;
    try {
      qrImageData = await QRCode.toDataURL(finalUrl, { errorCorrectionLevel: 'L', margin: 0, width: 180 });
    } catch (e) { console.warn("QR generation failed", e.message); }
    const updatedTable = buildTableRecord({
      qrUrl: finalUrl,
      qrGeneratedAt: new Date().toISOString()
    }, { existing: tableRecord });
    await saveTableRecord(updatedTable);
    // Emit table update event
    const allTables = await listTables();
    io.emit("tables:update", allTables.map(sanitizeTableResponse));
    res.json({ ok: true, url: finalUrl, qrImageData, table: sanitizeTableResponse(updatedTable) });
  } catch (e) {
    console.error("QR generation endpoint failed", e);
    res.status(500).json({ ok: false, message: "QR generation error" });
  }
});

app.post("/api/session/start", async (req, res) => {
  const { tableId, restoreUserId, sessionData } = req.body || {};
  const table = String(tableId || "").trim();
  if (!table) {
    return res.status(400).json({ ok: false, msg: "tableId required" });
  }

  const hasSessionData = Object.prototype.hasOwnProperty.call(req.body || {}, "sessionData");
  const normalizedSessionData = hasSessionData ? sanitizeSessionData(sessionData) : undefined;
  const requestedRestoreUserId = typeof restoreUserId === "string" && restoreUserId.trim().length
    ? restoreUserId.trim()
    : null;

  let session = null;
  let userId = null;
  let restored = false;

  if (requestedRestoreUserId) {
    const existing = await loadSession(requestedRestoreUserId);
    if (existing && existing.tableId === table) {
      restored = true;
      userId = existing.userId;
      session = await upsertSession({
        userId,
        tableId: table,
        userData: normalizedSessionData !== undefined ? normalizedSessionData : existing.userData
      });
    }
  }

  if (!session) {
    userId = uuidv4();
    session = await upsertSession({
      userId,
      tableId: table,
      userData: normalizedSessionData
    });
  }

  res.json({
    ok: true,
    session: session ? { ...session, restored } : null
  });
});

app.post("/api/validate-location", async (req, res) => {
  const { tableId, userId, lat, lng, sessionData, restoreUserId } = req.body || {};
  const table = String(tableId || "").trim();
  if (!table) {
    return res.status(400).json({ ok: false, msg: "tableId required" });
  }

  if (!lat || !lng) {
    console.log("[Location Check] Missing location:", { lat, lng });
    return res.status(400).json({ ok: false, msg: "Location required" });
  }

  if (Number.isNaN(CONFIG_LOCATION.lat) || Number.isNaN(CONFIG_LOCATION.lng)) {
    console.error("[Location Check] Server location not configured:", CONFIG_LOCATION);
    return res.status(500).json({ ok: false, msg: "Server location not configured" });
  }

  if (isAdminRequest(req)) {
    console.log("[Location Check] Admin bypass - allowing access");
    return res.json({ ok: true, inside: true, distance: 0, msg: "Admin bypass" });
  }

  const normalizedSessionData = Object.prototype.hasOwnProperty.call(req.body || {}, "sessionData")
    ? sanitizeSessionData(sessionData)
    : undefined;
  const requestedRestoreUserId = typeof restoreUserId === "string" && restoreUserId.trim().length
    ? restoreUserId.trim()
    : null;

  let activeUserId = typeof userId === "string" && userId.trim().length
    ? userId.trim()
    : null;
  let session = null;
  let sessionRestored = false;

  if (activeUserId) {
    const existing = await loadSession(activeUserId);
    if (existing && existing.tableId === table) {
      session = existing;
    } else {
      activeUserId = null;
    }
  }

  if (!session && requestedRestoreUserId) {
    const restored = await loadSession(requestedRestoreUserId);
    if (restored && restored.tableId === table) {
      session = restored;
      activeUserId = restored.userId;
      sessionRestored = true;
    }
  }

  if (!session) {
    activeUserId = activeUserId || uuidv4();
    session = await upsertSession({
      userId: activeUserId,
      tableId: table,
      userData: normalizedSessionData
    });
  } else {
    session = await upsertSession({
      userId: activeUserId,
      tableId: table,
      userData: normalizedSessionData !== undefined ? normalizedSessionData : session.userData
    });
  }

  const distance = dist(
    parseFloat(lat),
    parseFloat(lng),
    CONFIG_LOCATION.lat,
    CONFIG_LOCATION.lng
  );

  const allowed = distance <= CONFIG_LOCATION.radiusMeters;
  console.log("[Location Check]", {
    userLocation: { lat: parseFloat(lat), lng: parseFloat(lng) },
    restaurantLocation: { lat: CONFIG_LOCATION.lat, lng: CONFIG_LOCATION.lng },
    radius: CONFIG_LOCATION.radiusMeters,
    distance: Math.round(distance),
    allowed,
    userId: activeUserId,
    tableId: table
  });

  res.json({
    ok: allowed,
    inside: allowed,
    distance: Math.round(distance),
    session: session ? { ...session, restored: sessionRestored } : null,
    msg: allowed
      ? "Inside restaurant radius"
      : "Outside restaurant area, cannot place order"
  });
});

app.post("/api/validate-pin", async (req, res) => {
  const { tableId, pin } = req.body || {};
  const table = String(tableId || "").trim();
  if (!table || !pin) return res.status(400).json({ ok: false, msg: "tableId and pin required" });
  if (mongoDb) {
    const t = await mongoDb.collection("tables").findOne({ id: table });
    return res.json({ ok: !!t && bcrypt.compareSync(pin, t.pinHash) });
  } else {
    const d = await readData();
    const t = d.tables.find(x => String(x.id) === table);
    return res.json({ ok: t ? bcrypt.compareSync(pin, t.pinHash) : false });
  }
});

app.post("/api/orders/create", limiter, async (req, res) => {
  const { userId, tableId, items } = req.body || {};
  const table = String(tableId || "").trim();
  if (!table || !Array.isArray(items) || !items.length) {
    return res.status(400).json({ ok: false, msg: "tableId and items required" });
  }
  if (!userId) {
    return res.status(401).json({ ok: false, msg: "userId required" });
  }
  const session = await loadSession(userId);
  if (!session || session.tableId !== table) {
    return res.status(401).json({ ok: false, msg: "session invalid" });
  }
  const order = { id: uuidv4(), tableId: table, items, createdAt: new Date().toISOString() };
  if (mongoDb) {
    await mongoDb.collection("orders").insertOne({ ...order, _id: order.id });
    const all = await mongoDb.collection("orders").find({}).toArray();
    io.emit("orders:update", all);
  } else {
    const d = await readData();
    d.orders.push(order);
    await writeData(d);
    io.emit("orders:update", d.orders);
  }
  sendMail(order);
  res.json({ ok: true });
});

app.get("/api/orders", auth, async (req, res) => {
  let orders = [];
  if (mongoDb) {
    orders = await mongoDb.collection("orders").find({}).toArray();
  } else {
    const d = await readData();
    orders = d.orders || [];
  }
  res.json({ ok: true, orders });
});

app.get("/api/orders/summary", auth, async (req, res) => {
  let orders = [];
  if (mongoDb) {
    orders = await mongoDb.collection("orders").find({}).toArray();
  } else {
    const d = await readData();
    orders = d.orders || [];
  }

  const summary = {};

  // group by item name
  for (const order of orders) {
    for (const item of order.items) {
      const name = item.name;
      if (!summary[name]) {
        summary[name] = {
          itemName: name,
          totalQty: 0,
          tables: new Set()
        };
      }
      summary[name].totalQty += (item.qty || item.quantity || 0);
      summary[name].tables.add(order.tableId);
    }
  }

  // convert Set → Array for JSON
  const result = Object.values(summary).map(s => ({
    itemName: s.itemName,
    totalQty: s.totalQty,
    tables: Array.from(s.tables)
  }));

  res.json({ ok: true, data: result });
});

// ---------- Socket.IO ----------
io.on("connection", async s => {
  // Send initial orders
  if (mongoDb) {
    mongoDb.collection("orders").find({}).toArray().then(all => s.emit("orders:update", all));
  } else {
    readData().then(d => s.emit("orders:update", d.orders));
  }
  // Send initial tables
  const tables = await listTables();
  s.emit("tables:update", tables.map(sanitizeTableResponse));
});

// ---------- Start ----------
server.listen(PORT, () => console.log(`✅ Running on http://localhost:${PORT}`));
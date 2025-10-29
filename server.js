// IANO.DRS Billing Backend (Node.js + Express + Firebase)
import express from "express";
import cors from "cors";
import bodyParser from "body-parser";
import jwt from "jsonwebtoken";
import bcrypt from "bcryptjs";
import Joi from "joi";
import admin from "firebase-admin";
import { v4 as uuidv4 } from "uuid";

// --- Initialize Express App ---
const app = express();
app.use(cors());
app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: true }));

// --- Environment Variables ---
import dotenv from "dotenv";
dotenv.config();

const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || "default_secret";
const ADMIN_SECRET = process.env.ADMIN_SECRET || "default_admin_secret";
const FIREBASE_SERVICE_ACCOUNT_JSON = process.env.FIREBASE_SERVICE_ACCOUNT_JSON;
const FIREBASE_PROJECT_ID = process.env.FIREBASE_PROJECT_ID || "";

// --- Firebase Initialization ---
let db = null;
try {
  if (FIREBASE_SERVICE_ACCOUNT_JSON) {
    let serviceAccount = JSON.parse(
      Buffer.from(FIREBASE_SERVICE_ACCOUNT_JSON, "base64").toString("utf8")
    );

    admin.initializeApp({
      credential: admin.credential.cert(serviceAccount),
      projectId: FIREBASE_PROJECT_ID,
    });

    db = admin.firestore();
    console.log("✅ Firebase initialized successfully");
  } else {
    console.warn("⚠️ Firebase service account not found in env vars.");
  }
} catch (error) {
  console.error("🔥 Firebase initialization failed:", error.message);
}

// --- Middleware: Verify Token ---
function verifyToken(req, res, next) {
  const token = req.headers["authorization"]?.split(" ")[1];
  if (!token) return res.status(403).json({ message: "Token required" });

  jwt.verify(token, JWT_SECRET, (err, decoded) => {
    if (err) return res.status(401).json({ message: "Invalid token" });
    req.user = decoded;
    next();
  });
}

// --- Root & Health Routes ---
app.get("/", (req, res) => {
  res.json({
    status: "IANO.DRS Billing Backend Active",
    timestamp: new Date().toISOString(),
  });
});

app.get("/health", (req, res) => {
  res.json({ ok: true, timestamp: new Date().toISOString() });
});

// --- Registration Schema ---
const registerSchema = Joi.object({
  name: Joi.string().required(),
  email: Joi.string().email().required(),
  password: Joi.string().min(6).required(),
});

// --- Register User ---
app.post("/register", async (req, res) => {
  if (!db) return res.status(503).json({ message: "Database not initialized" });

  const { error } = registerSchema.validate(req.body);
  if (error) return res.status(400).json({ message: error.details[0].message });

  const { name, email, password } = req.body;
  try {
    const userRef = db.collection("users").doc(email);
    const doc = await userRef.get();
    if (doc.exists)
      return res.status(400).json({ message: "User already exists" });

    const hashed = await bcrypt.hash(password, 10);
    await userRef.set({
      name,
      email,
      password: hashed,
      createdAt: new Date().toISOString(),
      balance: 0,
      role: "user",
    });

    res.json({ message: "User registered successfully" });
  } catch (err) {
    res.status(500).json({ message: "Server error", error: err.message });
  }
});

// --- Login ---
app.post("/login", async (req, res) => {
  if (!db) return res.status(503).json({ message: "Database not initialized" });

  const { email, password } = req.body;
  try {
    const userRef = db.collection("users").doc(email);
    const doc = await userRef.get();
    if (!doc.exists)
      return res.status(400).json({ message: "Invalid credentials" });

    const user = doc.data();
    const valid = await bcrypt.compare(password, user.password);
    if (!valid)
      return res.status(400).json({ message: "Invalid credentials" });

    const token = jwt.sign(
      { email: user.email, role: user.role },
      JWT_SECRET,
      { expiresIn: "7d" }
    );

    res.json({ token, user: { name: user.name, email: user.email } });
  } catch (err) {
    res.status(500).json({ message: "Server error", error: err.message });
  }
});

// --- Create Admin ---
app.post("/create-admin", async (req, res) => {
  if (!db) return res.status(503).json({ message: "Database not initialized" });

  const { secret, name, email, password } = req.body;
  if (secret !== ADMIN_SECRET)
    return res.status(403).json({ message: "Unauthorized" });

  try {
    const userRef = db.collection("users").doc(email);
    const doc = await userRef.get();
    if (doc.exists)
      return res.status(400).json({ message: "Admin already exists" });

    const hashed = await bcrypt.hash(password, 10);
    await userRef.set({
      name,
      email,
      password: hashed,
      role: "admin",
      createdAt: new Date().toISOString(),
    });

    res.json({ message: "Admin account created successfully" });
  } catch (err) {
    res.status(500).json({ message: "Server error", error: err.message });
  }
});

// --- Admin: Generate Voucher ---
app.post("/admin/vouchers/generate", verifyToken, async (req, res) => {
  if (!db) return res.status(503).json({ message: "Database not initialized" });
  if (req.user.role !== "admin")
    return res.status(403).json({ message: "Access denied" });

  const { amount } = req.body;
  if (!amount || isNaN(amount))
    return res.status(400).json({ message: "Invalid voucher amount" });

  const code = uuidv4().slice(0, 8).toUpperCase();
  try {
    await db.collection("vouchers").doc(code).set({
      code,
      amount: Number(amount),
      used: false,
      createdAt: new Date().toISOString(),
    });

    res.json({ message: "Voucher generated", code, amount });
  } catch (err) {
    res.status(500).json({ message: "Error generating voucher", error: err.message });
  }
});

// --- User: Redeem Voucher ---
app.post("/vouchers/redeem", verifyToken, async (req, res) => {
  if (!db) return res.status(503).json({ message: "Database not initialized" });

  const { code } = req.body;
  if (!code) return res.status(400).json({ message: "Voucher code required" });

  try {
    const voucherRef = db.collection("vouchers").doc(code);
    const voucherDoc = await voucherRef.get();

    if (!voucherDoc.exists)
      return res.status(404).json({ message: "Voucher not found" });

    const voucher = voucherDoc.data();
    if (voucher.used)
      return res.status(400).json({ message: "Voucher already used" });

    const userRef = db.collection("users").doc(req.user.email);
    const userDoc = await userRef.get();
    const balance = (userDoc.data().balance || 0) + voucher.amount;

    await userRef.update({ balance });
    await voucherRef.update({ used: true, usedBy: req.user.email });

    await db.collection("transactions").add({
      type: "voucher_redeem",
      user: req.user.email,
      amount: voucher.amount,
      code,
      timestamp: new Date().toISOString(),
    });

    res.json({ message: "Voucher redeemed", newBalance: balance });
  } catch (err) {
    res.status(500).json({ message: "Error redeeming voucher", error: err.message });
  }
});

// --- Billing Summary ---
app.get("/billing/summary", verifyToken, async (req, res) => {
  if (!db) return res.status(503).json({ message: "Database not initialized" });

  try {
    const userRef = db.collection("users").doc(req.user.email);
    const doc = await userRef.get();
    if (!doc.exists) return res.status(404).json({ message: "User not found" });

    const user = doc.data();
    res.json({
      balance: user.balance || 0,
      email: user.email,
      name: user.name,
    });
  } catch (err) {
    res.status(500).json({ message: "Error fetching billing summary", error: err.message });
  }
});

// --- Maintenance Reports ---
app.post("/maintenance/report", verifyToken, async (req, res) => {
  if (!db) return res.status(503).json({ message: "Database not initialized" });

  const { title, description } = req.body;
  if (!title || !description)
    return res.status(400).json({ message: "Title and description required" });

  try {
    await db.collection("maintenance_reports").add({
      user: req.user.email,
      title,
      description,
      status: "pending",
      createdAt: new Date().toISOString(),
    });

    res.json({ message: "Report submitted successfully" });
  } catch (err) {
    res.status(500).json({ message: "Error submitting report", error: err.message });
  }
});

// --- Start Server ---
app.listen(PORT, () => {
  console.log(`🚀 IANO.DRS Billing Backend running on port ${PORT}`);
});

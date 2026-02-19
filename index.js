require("dotenv").config();
const express = require("express");
const cors = require("cors");
const jwt = require("jsonwebtoken");
const { createClient } = require("@supabase/supabase-js");
const axios = require("axios");
const qs = require("qs");
const rateLimit = require("express-rate-limit");
const NodeCache = require("node-cache");
const crypto = require("crypto"); // Added for timing-safe checks and secure keys

const app = express();
const tokenCache = new NodeCache({ stdTTL: 3600, checkperiod: 600 }); 
// New: Cache the "is_active" status for 5 mins to prevent Patreon API spam
const statusCache = new NodeCache({ stdTTL: 300 }); 

// ======================================================
// CONFIG & MIDDLEWARE
// ======================================================
const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET;
const REFRESH_SECRET = process.env.REFRESH_SECRET;
const REQUIRED_TIER_ID = String(process.env.PATREON_REQUIRED_TIER_ID || "").trim();
const ADMIN_SECRET = process.env.ADMIN_SECRET;

const allowedOrigins = (process.env.ALLOWED_ORIGINS || "").split(",").map(o => o.trim());

app.use(cors({
    origin: function (origin, callback) {
        if (!origin || allowedOrigins.indexOf(origin) !== -1 || allowedOrigins.includes("*")) {
            callback(null, true);
        } else {
            callback(new Error('Not allowed by CORS'));
        }
    },
    allowedHeaders: ["Content-Type", "Authorization", "ngrok-skip-browser-warning"],
    credentials: true
}));

app.use(express.json());

const supabase = createClient(process.env.SUPABASE_URL, process.env.SUPABASE_KEY);

// RATE LIMITERS
const authLimiter = rateLimit({
    windowMs: 15 * 60 * 1000,
    max: 15,
    message: { success: false, message: "Too many attempts. Try again later." },
    standardHeaders: true,
    legacyHeaders: false,
});

const globalLimiter = rateLimit({
    windowMs: 1 * 60 * 1000,
    max: 60,
    message: { success: false, message: "Rate limit exceeded." }
});

app.use(globalLimiter);

// ======================================================
// HELPERS
// ======================================================
const cleanId = (id) => String(id || "").trim().replace(/['"]/g, '');

// NEW: Timing-safe comparison to prevent brute force on admin secret
const safeCompare = (input, secret) => {
    if (!input || !secret) return false;
    const inputBuf = Buffer.from(input);
    const secretBuf = Buffer.from(secret);
    if (inputBuf.length !== secretBuf.length) return false;
    return crypto.timingSafeEqual(inputBuf, secretBuf);
};

// NEW: Secure random generation (Math.random is predictable)
const generateSecureKey = () => {
    const p1 = crypto.randomBytes(3).toString('hex').toUpperCase();
    const p2 = crypto.randomBytes(3).toString('hex').toUpperCase();
    return `PRO-${p1}-${p2}`;
};

let cachedCreatorId = null;
async function getCreatorId() {
  if (cachedCreatorId) return cachedCreatorId;
  try {
    const res = await axios.get("https://www.patreon.com/api/oauth2/v2/identity", {
      headers: { Authorization: `Bearer ${process.env.PATREON_CREATOR_ACCESS_TOKEN}` }
    });
    cachedCreatorId = String(res.data.data.id);
    return cachedCreatorId;
  } catch (err) {
    console.error("CRITICAL: Could not fetch Creator ID.");
    return null;
  }
}

const getDurationMs = (durationStr) => {
  const defaultMs = 30 * 24 * 60 * 60 * 1000;
  if (!durationStr || durationStr.toLowerCase() === "null") return defaultMs;
  const match = durationStr.match(/(\d+)\s*(day|hour|minute|second)/i);
  if (!match) return defaultMs;
  const value = parseInt(match[1]);
  const unit = match[2].toLowerCase();
  switch (unit) {
    case "day": return value * 24 * 60 * 60 * 1000;
    case "hour": return value * 60 * 60 * 1000;
    case "minute": return value * 60 * 1000;
    case "second": return value * 1000;
    default: return defaultMs;
  }
};

const sendAuthWindowResponse = (res, data) => {
  const isError = data.type === 'PATREON_ERROR';
  const themeColor = isError ? '#ff4b5c' : '#00d1b2';
  const glowColor = isError ? 'rgba(255, 75, 92, 0.2)' : 'rgba(0, 209, 178, 0.2)';

  res.send(`
    <html>
      <head>
        <meta name="viewport" content="width=device-width, initial-scale=1">
        <style>
          @import url('https://fonts.googleapis.com/css2?family=Inter:wght@400;600;700&display=swap');
          body { font-family: 'Inter', sans-serif; display: flex; align-items: center; justify-content: center; height: 100vh; margin: 0; background-color: #0f172a; }
          .container { text-align: center; padding: 40px; background: rgba(30, 41, 59, 0.7); backdrop-filter: blur(12px); border: 1px solid rgba(255, 255, 255, 0.1); border-radius: 24px; box-shadow: 0 20px 50px rgba(0, 0, 0, 0.3); max-width: 340px; width: 90%; animation: slideUp 0.6s cubic-bezier(0.16, 1, 0.3, 1); }
          @keyframes slideUp { from { opacity: 0; transform: translateY(20px); } to { opacity: 1; transform: translateY(0); } }
          .icon-circle { width: 64px; height: 64px; border-radius: 50%; background: ${glowColor}; display: flex; align-items: center; justify-content: center; margin: 0 auto 24px; color: ${themeColor}; font-size: 32px; border: 2px solid ${themeColor}; }
          h2 { color: #f8fafc; margin: 0 0 12px; font-weight: 700; letter-spacing: -0.02em; }
          p { color: #94a3b8; line-height: 1.6; margin: 0 0 24px; font-size: 15px; }
          .loader { height: 4px; width: 100%; background: rgba(255,255,255,0.05); border-radius: 2px; overflow: hidden; position: relative; }
          .progress { height: 100%; background: ${themeColor}; width: 0%; animation: progressAnim ${isError ? '4s' : '1.5s'} linear forwards; }
          @keyframes progressAnim { to { width: 100%; } }
        </style>
      </head>
      <body>
        <div class="container">
          <div class="icon-circle">${isError ? '✕' : '✓'}</div>
          <h2>${isError ? 'Upgrade Required' : 'Verified'}</h2>
          <p>${data.message}</p>
          <div class="loader"><div class="progress"></div></div>
          <script>
            window.opener.postMessage(${JSON.stringify(data)}, "*");
            setTimeout(() => { window.close(); }, ${isError ? 4000 : 1500});
          </script>
        </div>
      </body>
    </html>
  `);
};

// ======================================================
// 1. PATREON AUTH FLOW
// ======================================================
app.get("/auth/patreon", authLimiter, (req, res) => {
  const redirectUri = encodeURIComponent(process.env.PATREON_REDIRECT_URI);
  const url = `https://www.patreon.com/oauth2/authorize?response_type=code&client_id=${process.env.PATREON_CLIENT_ID}&redirect_uri=${redirectUri}&scope=identity%20identity.memberships%20identity[email]`;
  res.redirect(url);
});

app.get("/auth/patreon/callback", async (req, res) => {
  const { code } = req.query;
  try {
    const tokenRes = await axios.post("https://www.patreon.com/api/oauth2/token", qs.stringify({
      code, grant_type: "authorization_code",
      client_id: process.env.PATREON_CLIENT_ID,
      client_secret: process.env.PATREON_CLIENT_SECRET,
      redirect_uri: process.env.PATREON_REDIRECT_URI,
    }), { headers: { "Content-Type": "application/x-www-form-urlencoded" } });

    const userAccessToken = tokenRes.data.access_token;
    const userRes = await axios.get("https://www.patreon.com/api/oauth2/v2/identity?include=memberships.currently_entitled_tiers&fields[user]=email&fields[member]=patron_status", {
      headers: { Authorization: `Bearer ${userAccessToken}` }
    });

    const userData = userRes.data;
    const email = userData.data.attributes.email;
    const patId = String(userData.data.id);
    const creatorId = await getCreatorId();

    const memberships = (userData.included || []).filter(m => m.type === "member");
    const isCreator = (creatorId && patId === creatorId);

    const isMember = memberships.some(m => {
      const status = m.attributes?.patron_status;
      const tierIds = (m.relationships?.currently_entitled_tiers?.data || []).map(t => cleanId(t.id));
      return tierIds.includes(REQUIRED_TIER_ID) && (status === "active_patron" || status === null);
    });

    if (!isMember && !isCreator) {
      return sendAuthWindowResponse(res, { 
        type: 'PATREON_ERROR', 
        message: `This feature requires a Pro subscription.` 
      });
    }

    // Fixed key naming (consistent with validate-token)
    tokenCache.set(`pat_token_${patId}`, userAccessToken, 3600);

    const jwtToken = jwt.sign(
      { id: `pat-${patId}`, email, authType: "patreon" },
      JWT_SECRET, { expiresIn: "30m" }
    );

    const refreshToken = jwt.sign(
      { id: `pat-${patId}`, authType: "patreon" },
      REFRESH_SECRET, { expiresIn: "7d" }
    );

    return sendAuthWindowResponse(res, { 
      type: 'PATREON_SUCCESS', 
      token: jwtToken, 
      refreshToken: refreshToken,
      email: email,
      message: "Pro status verified. Loading application..." 
    });

  } catch (err) {
    console.error("Auth Callback Error:", err.response?.data || err.message);
    res.status(500).send("Login Failed");
  }
});

// ======================================================
// 2. LIVE HEARTBEAT & REFRESH
// ======================================================

app.post("/refresh-session", authLimiter, async (req, res) => {
    const { refreshToken } = req.body;
    if (!refreshToken) return res.status(401).json({ success: false });

    try {
        const decoded = jwt.verify(refreshToken, REFRESH_SECRET);
        const newToken = jwt.sign(
            { id: decoded.id, email: decoded.email, authType: decoded.authType },
            JWT_SECRET, { expiresIn: "30m" }
        );
        res.json({ success: true, token: newToken });
    } catch (e) {
        res.status(401).json({ success: false, message: "Refresh expired" });
    }
});

app.get("/validate-token", async (req, res) => {
  const token = req.headers.authorization?.split(" ")[1];
  if (!token) return res.status(401).json({ valid: false });

  try {
    const decoded = jwt.verify(token, JWT_SECRET);

    // --- LICENSE VALIDATION ---
    if (decoded.authType === "license") {
      const { data: lic } = await supabase.from("licenses").select("*").eq("id", decoded.id).single();
      
      // Check if time is up
      const isPastTime = lic && lic.expires_at && new Date(lic.expires_at) < new Date();
      
      if (isPastTime) {
          // SELF-HEALING: If code sees it's expired, update the text in the DB
          if (lic.status !== "expired") {
              await supabase.from("licenses").update({ status: "expired" }).eq("id", lic.id);
          }
          return res.status(401).json({ valid: false, reason: "expired" });
      }

      const isValid = lic && lic.status === "active";
      return isValid ? res.json({ valid: true }) : res.status(401).json({ valid: false });
    }

    // --- PATREON VALIDATION ---
    if (decoded.authType === "patreon") {
      if (statusCache.get(`active_${decoded.id}`)) return res.json({ valid: true });

      const userAccessToken = tokenCache.get(`pat_token_${decoded.id}`);
      if (!userAccessToken) return res.status(401).json({ valid: false });

      const live = await axios.get("https://www.patreon.com/api/oauth2/v2/identity?include=memberships.currently_entitled_tiers&fields[member]=patron_status", {
        headers: { Authorization: `Bearer ${userAccessToken}` }
      });
      
      const patId = String(live.data.data.id);
      const creatorId = await getCreatorId();
      let active = (creatorId && patId === creatorId);

      if (!active) {
          const memberships = (live.data.included || []).filter(m => m.type === "member");
          active = memberships.some(m => {
              const status = m.attributes?.patron_status;
              const tierIds = (m.relationships?.currently_entitled_tiers?.data || []).map(t => cleanId(t.id));
              return tierIds.includes(REQUIRED_TIER_ID) && (status === "active_patron" || status === null);
          });
      }

      if (active) {
          statusCache.set(`active_${decoded.id}`, true);
          return res.json({ valid: true });
      }
      return res.status(401).json({ valid: false });
    }
  } catch (err) {
    return res.status(401).json({ valid: false });
  }
});
// ======================================================
// 3. ADMIN & VERIFY
// ======================================================
app.post("/verify", authLimiter, async (req, res) => {
  const { email, license_key } = req.body;
  try {
    const { data: lic, error } = await supabase.from("licenses").select("*").eq("email", email).eq("license_key", license_key).single();
    if (error || !lic || lic.status === "revoked") return res.status(403).json({ success: false, message: "Invalid Key" });

    const now = new Date();

    // If already used, check if the time has run out
    if (lic.is_used && lic.expires_at) {
      if (new Date(lic.expires_at) < now) {
          // SELF-HEALING: Update DB status to expired
          await supabase.from("licenses").update({ status: "expired" }).eq("id", lic.id);
          return res.status(403).json({ success: false, message: "Expired" });
      }
    } 
    // If NOT used yet, start the timer now
    else {
      const ms = getDurationMs(lic.plan_duration);
      const { data: updated } = await supabase.from("licenses").update({
        is_used: true, 
        expires_at: new Date(now.getTime() + ms).toISOString(), 
        status: "active"
      }).eq("id", lic.id).select().single();
      lic.id = updated.id; // update local ref
      lic.email = updated.email;
    }

    const token = jwt.sign({ id: lic.id, email: lic.email, authType: "license" }, JWT_SECRET, { expiresIn: "24h" });
    res.json({ success: true, token });
  } catch (e) { 
      res.status(500).json({ success: false }); 
  }
});

app.post("/generate", authLimiter, async (req, res) => {
  const { email, plan_duration, admin_secret } = req.body;
  
  // Timing-safe secret check
  if (!safeCompare(admin_secret, ADMIN_SECRET)) {
      return res.status(401).json({ success: false });
  }

  const key = generateSecureKey();
  const { data } = await supabase.from("licenses").insert([{ 
      email, 
      license_key: key, 
      plan_duration: plan_duration || "30 days", 
      status: "active",
      is_used: false // Explicitly false so expiration doesn't start yet
  }]).select().single();
  
  res.json({ success: true, license: data });
});

app.listen(PORT, () => console.log(`🚀 Secure Server running on port ${PORT}`));
const crypto = require("crypto");
const axios = require("axios");
const supabase = require("./_supabase");

const JWT_SECRET = process.env.JWT_SECRET;
const REFRESH_SECRET = process.env.REFRESH_SECRET;
const REQUIRED_TIER_ID = String(process.env.PATREON_REQUIRED_TIER_ID || "").trim();
const ADMIN_SECRET = process.env.ADMIN_SECRET;

const cleanId = (id) => String(id || "").trim().replace(/['"]/g, "");

const safeCompare = (input, secret) => {
  if (!input || !secret) return false;
  const inputBuf = Buffer.from(input);
  const secretBuf = Buffer.from(secret);
  if (inputBuf.length !== secretBuf.length) return false;
  return crypto.timingSafeEqual(inputBuf, secretBuf);
};

const generateSecureKey = () => {
  const p1 = crypto.randomBytes(3).toString("hex").toUpperCase();
  const p2 = crypto.randomBytes(3).toString("hex").toUpperCase();
  return `PRO-${p1}-${p2}`;
};

const getDurationMs = (durationStr) => {
  const defaultMs = 30 * 24 * 60 * 60 * 1000;
  if (!durationStr || durationStr.toLowerCase() === "null") return defaultMs;
  const match = durationStr.match(/(\d+)\s*(day|hour|minute|second)/i);
  if (!match) return defaultMs;
  const value = parseInt(match[1]);
  const unit = match[2].toLowerCase();
  switch (unit) {
    case "day":    return value * 24 * 60 * 60 * 1000;
    case "hour":   return value * 60 * 60 * 1000;
    case "minute": return value * 60 * 1000;
    case "second": return value * 1000;
    default:       return defaultMs;
  }
};

// Store Patreon access token in Supabase (replaces in-memory NodeCache)
const storePatreonToken = async (patId, accessToken) => {
  await supabase.from("patreon_tokens").upsert({
    patreon_id: patId,
    access_token: accessToken,
    updated_at: new Date().toISOString(),
  });
};

// Get Patreon access token from Supabase
const getPatreonToken = async (patId) => {
  const { data } = await supabase
    .from("patreon_tokens")
    .select("access_token")
    .eq("patreon_id", patId)
    .single();
  return data?.access_token || null;
};

let cachedCreatorId = null;
const getCreatorId = async () => {
  if (cachedCreatorId) return cachedCreatorId;
  try {
    const res = await axios.get("https://www.patreon.com/api/oauth2/v2/identity", {
      headers: { Authorization: `Bearer ${process.env.PATREON_CREATOR_ACCESS_TOKEN}` },
    });
    cachedCreatorId = String(res.data.data.id);
    return cachedCreatorId;
  } catch (err) {
    console.error("CRITICAL: Could not fetch Creator ID.");
    return null;
  }
};

const checkMembership = (userData, creatorId) => {
  const patId = String(userData.data.id);
  const memberships = (userData.included || []).filter((m) => m.type === "member");
  const isCreator = creatorId && patId === creatorId;
  const isMember = memberships.some((m) => {
    const status = m.attributes?.patron_status;
    const tierIds = (m.relationships?.currently_entitled_tiers?.data || []).map((t) => cleanId(t.id));
    return tierIds.includes(REQUIRED_TIER_ID) && (status === "active_patron" || status === null);
  });
  return isMember || isCreator;
};

const setCors = (req, res) => {
  res.setHeader("Access-Control-Allow-Origin", "*");
  res.setHeader("Access-Control-Allow-Methods", "GET, POST, OPTIONS");
  res.setHeader("Access-Control-Allow-Headers", "Content-Type, Authorization, ngrok-skip-browser-warning");
  res.setHeader("Access-Control-Allow-Credentials", "true");
};

const sendAuthWindowResponse = (res, data) => {
  const isError = data.type === "PATREON_ERROR";
  const themeColor = isError ? "#ff4b5c" : "#00d1b2";
  const glowColor = isError ? "rgba(255, 75, 92, 0.2)" : "rgba(0, 209, 178, 0.2)";
  res.setHeader("Content-Type", "text/html");
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
          .loader { height: 4px; width: 100%; background: rgba(255,255,255,0.05); border-radius: 2px; overflow: hidden; }
          .progress { height: 100%; background: ${themeColor}; width: 0%; animation: progressAnim ${isError ? "4s" : "1.5s"} linear forwards; }
          @keyframes progressAnim { to { width: 100%; } }
        </style>
      </head>
      <body>
        <div class="container">
          <div class="icon-circle">${isError ? "✕" : "✓"}</div>
          <h2>${isError ? "Upgrade Required" : "Verified"}</h2>
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

module.exports = {
  JWT_SECRET, REFRESH_SECRET, REQUIRED_TIER_ID, ADMIN_SECRET,
  cleanId, safeCompare, generateSecureKey, getDurationMs,
  storePatreonToken, getPatreonToken, getCreatorId,
  checkMembership, setCors, sendAuthWindowResponse,
};

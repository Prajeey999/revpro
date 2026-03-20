const axios = require("axios");
const jwt = require("jsonwebtoken");
const { supabase, setCors, getPatreonToken, getCreatorId, checkMembership } = require("./_helpers");

module.exports = async (req, res) => {
  setCors(req, res);
  if (req.method === "OPTIONS") return res.status(200).end();

  const token = req.headers.authorization?.split(" ")[1];
  if (!token) return res.status(401).json({ valid: false });

  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET);

    if (decoded.authType === "license") {
      const { data: lic } = await supabase.from("licenses").select("*").eq("id", decoded.id).single();
      const isPastTime = lic && lic.expires_at && new Date(lic.expires_at) < new Date();
      if (isPastTime) {
        if (lic.status !== "expired")
          await supabase.from("licenses").update({ status: "expired" }).eq("id", lic.id);
        return res.status(401).json({ valid: false, reason: "expired" });
      }
      return lic && lic.status === "active"
        ? res.json({ valid: true })
        : res.status(401).json({ valid: false });
    }

    if (decoded.authType === "patreon") {
      const userAccessToken = await getPatreonToken(decoded.id.replace("pat-", ""));
      console.log("patreon id:", decoded.id);
      console.log("has token:", !!userAccessToken);

      if (!userAccessToken) return res.status(401).json({ valid: false, reason: "no_patreon_token" });

      const live = await axios.get(
        "https://www.patreon.com/api/oauth2/v2/identity?include=memberships.currently_entitled_tiers&fields[member]=patron_status",
        { headers: { Authorization: `Bearer ${userAccessToken}` } }
      );

      console.log("patreon memberships:", JSON.stringify(live.data.included));
      console.log("REQUIRED_TIER_ID:", process.env.PATREON_REQUIRED_TIER_ID);

      const creatorId = await getCreatorId();
      console.log("creatorId:", creatorId);
      console.log("patId:", live.data.data.id);

      const active = checkMembership(live.data, creatorId);
      console.log("active:", active);

      return active ? res.json({ valid: true }) : res.status(401).json({ valid: false, reason: "not_active_patron" });
    }

    return res.status(401).json({ valid: false, reason: "unknown_auth_type" });
  } catch (err) {
    console.log("validate-token error:", err.message);
    return res.status(401).json({ valid: false });
  }
};

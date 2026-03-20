const jwt = require("jsonwebtoken");
const axios = require("axios");
const supabase = require("../lib/supabase");
const {
  JWT_SECRET, REQUIRED_TIER_ID,
  cleanId, getCreatorId, getPatreonToken, setCors,
} = require("../lib/helpers");

module.exports = async (req, res) => {
  setCors(req, res);
  if (req.method === "OPTIONS") return res.status(200).end();

  const token = req.headers.authorization?.split(" ")[1];
  if (!token) return res.status(401).json({ valid: false });

  try {
    const decoded = jwt.verify(token, JWT_SECRET);

    // --- LICENSE VALIDATION ---
    if (decoded.authType === "license") {
      const { data: lic } = await supabase
        .from("licenses")
        .select("*")
        .eq("id", decoded.id)
        .single();

      const isPastTime = lic && lic.expires_at && new Date(lic.expires_at) < new Date();
      if (isPastTime) {
        if (lic.status !== "expired") {
          await supabase.from("licenses").update({ status: "expired" }).eq("id", lic.id);
        }
        return res.status(401).json({ valid: false, reason: "expired" });
      }

      const isValid = lic && lic.status === "active";
      return isValid
        ? res.json({ valid: true })
        : res.status(401).json({ valid: false });
    }

    // --- PATREON VALIDATION ---
    if (decoded.authType === "patreon") {
      const patId = decoded.id.replace("pat-", "");
      const userAccessToken = await getPatreonToken(patId);
      if (!userAccessToken) return res.status(401).json({ valid: false });

      const live = await axios.get(
        "https://www.patreon.com/api/oauth2/v2/identity?include=memberships.currently_entitled_tiers&fields[member]=patron_status",
        { headers: { Authorization: `Bearer ${userAccessToken}` } }
      );

      const livePatId = String(live.data.data.id);
      const creatorId = await getCreatorId();
      let active = creatorId && livePatId === creatorId;

      if (!active) {
        const memberships = (live.data.included || []).filter((m) => m.type === "member");
        active = memberships.some((m) => {
          const status = m.attributes?.patron_status;
          const tierIds = (m.relationships?.currently_entitled_tiers?.data || []).map((t) => cleanId(t.id));
          return tierIds.includes(REQUIRED_TIER_ID) && (status === "active_patron" || status === null);
        });
      }

      return active
        ? res.json({ valid: true })
        : res.status(401).json({ valid: false });
    }

    // Unknown auth type
    return res.status(401).json({ valid: false, reason: "unknown_auth_type" });

  } catch (err) {
    return res.status(401).json({ valid: false });
  }
};

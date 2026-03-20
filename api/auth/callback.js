const axios = require("axios");
const qs = require("qs");
const jwt = require("jsonwebtoken");
const { cleanId, savePatreonToken, getCreatorId, sendAuthWindowResponse, REQUIRED_TIER_ID } = require("../_helpers");

module.exports = async (req, res) => {
  const { code } = req.query;
  try {
    const tokenRes = await axios.post(
      "https://www.patreon.com/api/oauth2/token",
      qs.stringify({
        code,
        grant_type: "authorization_code",
        client_id: process.env.PATREON_CLIENT_ID,
        client_secret: process.env.PATREON_CLIENT_SECRET,
        redirect_uri: process.env.PATREON_REDIRECT_URI,
      }),
      { headers: { "Content-Type": "application/x-www-form-urlencoded" } }
    );

    const userAccessToken = tokenRes.data.access_token;
    const userRes = await axios.get(
      "https://www.patreon.com/api/oauth2/v2/identity?include=memberships.currently_entitled_tiers&fields[user]=email&fields[member]=patron_status",
      { headers: { Authorization: `Bearer ${userAccessToken}` } }
    );

    const userData = userRes.data;
    const email = userData.data.attributes.email;
    const patId = String(userData.data.id);
    const creatorId = await getCreatorId(axios);

    const memberships = (userData.included || []).filter((m) => m.type === "member");
    const isCreator = creatorId && patId === creatorId;

    const isMember = memberships.some((m) => {
      const status = m.attributes?.patron_status;
      const tierIds = (m.relationships?.currently_entitled_tiers?.data || []).map((t) => cleanId(t.id));
      return tierIds.includes(REQUIRED_TIER_ID) && (status === "active_patron" || status === null);
    });

    if (!isMember && !isCreator) {
      return sendAuthWindowResponse(res, {
        type: "PATREON_ERROR",
        message: "This feature requires a Pro subscription.",
      });
    }

    await savePatreonToken(`pat-${patId}`, userAccessToken);

    const jwtToken = jwt.sign(
      { id: `pat-${patId}`, email, authType: "patreon" },
      process.env.JWT_SECRET,
      { expiresIn: "30m" }
    );

    const refreshToken = jwt.sign(
      { id: `pat-${patId}`, email, authType: "patreon" },
      process.env.REFRESH_SECRET,
      { expiresIn: "7d" }
    );

    return sendAuthWindowResponse(res, {
      type: "PATREON_SUCCESS",
      token: jwtToken,
      refreshToken: refreshToken,
      email: email,
      message: "Pro status verified. Loading application...",
    });
  } catch (err) {
    console.error("Callback Error:", err.response?.data || err.message);
    res.status(500).send("Login Failed");
  }
};

const axios = require("axios");
const qs = require("qs");
const jwt = require("jsonwebtoken");
const { storePatreonToken, getCreatorId, checkMembership } = require("../_helpers");

module.exports = async (req, res) => {
  const { code } = req.query;
  try {
    const tokenRes = await axios.post(
      "https://www.patreon.com/api/oauth2/token",
      qs.stringify({
        code, grant_type: "authorization_code",
        client_id: process.env.PATREON_CLIENT_ID,
        client_secret: process.env.PATREON_CLIENT_SECRET,
        redirect_uri: process.env.PATREON_REDIRECT_URI_MOBILE,
      }),
      { headers: { "Content-Type": "application/x-www-form-urlencoded" } }
    );

    const userAccessToken = tokenRes.data.access_token;
    const userRes = await axios.get(
      "https://www.patreon.com/api/oauth2/v2/identity?include=memberships.currently_entitled_tiers&fields[user]=email&fields[member]=patron_status",
      { headers: { Authorization: `Bearer ${userAccessToken}` } }
    );

    const email = userRes.data.data.attributes.email;
    const patId = String(userRes.data.data.id);
    const creatorId = await getCreatorId();
    const isAllowed = checkMembership(userRes.data, creatorId);

    if (!isAllowed) {
      return res.redirect(
        `analyticspro://callback?error=true&message=${encodeURIComponent("Pro subscription required")}`
      );
    }

    await storePatreonToken(patId, userAccessToken);

    const jwtToken = jwt.sign(
      { id: `pat-${patId}`, email, authType: "patreon" },
      process.env.JWT_SECRET, { expiresIn: "30m" }
    );
    const refreshToken = jwt.sign(
      { id: `pat-${patId}`, email, authType: "patreon" },
      process.env.REFRESH_SECRET, { expiresIn: "7d" }
    );

    return res.redirect(
      `analyticspro://callback?token=${jwtToken}&refreshToken=${refreshToken}&email=${encodeURIComponent(email)}`
    );
  } catch (err) {
    console.error("Mobile Callback Error:", err.response?.data || err.message);
    return res.redirect(
      `analyticspro://callback?error=true&message=${encodeURIComponent("Login failed. Please try again.")}`
    );
  }
};
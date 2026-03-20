const { setCors } = require("../../lib/helpers");

module.exports = async (req, res) => {
  setCors(req, res);
  if (req.method === "OPTIONS") return res.status(200).end();

  const redirectUri = encodeURIComponent(process.env.PATREON_REDIRECT_URI);
  const url = `https://www.patreon.com/oauth2/authorize?response_type=code&client_id=${process.env.PATREON_CLIENT_ID}&redirect_uri=${redirectUri}&scope=identity%20identity.memberships%20identity[email]`;
  res.redirect(url);
};

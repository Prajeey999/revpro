const { applyCors } = require("../_helpers");

module.exports = (req, res) => {
  applyCors(req, res);
  if (req.method === "OPTIONS") return res.status(200).end();

  const redirectUri = encodeURIComponent(process.env.PATREON_REDIRECT_URI_MOBILE);
  const url = `https://www.patreon.com/oauth2/authorize?response_type=code&client_id=${process.env.PATREON_CLIENT_ID}&redirect_uri=${redirectUri}&scope=identity%20identity.memberships%20identity[email]`;
  res.redirect(url);
};

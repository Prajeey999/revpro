const jwt = require("jsonwebtoken");
const { setCors } = require("./_helpers");

module.exports = async (req, res) => {
  setCors(req, res);
  if (req.method === "OPTIONS") return res.status(200).end();

  const { refreshToken } = req.body;
  if (!refreshToken) return res.status(401).json({ success: false });

  try {
    const decoded = jwt.verify(refreshToken, process.env.REFRESH_SECRET);
    const newToken = jwt.sign(
      { id: decoded.id, email: decoded.email, authType: decoded.authType },
      process.env.JWT_SECRET,
      { expiresIn: "30m" }
    );
    res.json({ success: true, token: newToken });
  } catch (e) {
    res.status(401).json({ success: false, message: "Refresh expired" });
  }
};
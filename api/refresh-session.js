const jwt = require('jsonwebtoken');
const { handleCors } = require('../lib/cors');

module.exports = async (req, res) => {
  if (handleCors(req, res)) return;
  if (req.method !== 'POST') return res.status(405).end();

  const { refreshToken } = req.body;
  if (!refreshToken) return res.status(401).json({ success: false });

  try {
    const decoded = jwt.verify(refreshToken, process.env.REFRESH_SECRET);
    const newToken = jwt.sign(
      { id: decoded.id, email: decoded.email, authType: decoded.authType },
      process.env.JWT_SECRET,
      { expiresIn: '30m' }
    );
    res.json({ success: true, token: newToken });
  } catch {
    res.status(401).json({ success: false, message: 'Refresh expired' });
  }
};

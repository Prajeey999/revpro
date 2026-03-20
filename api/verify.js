const jwt = require('jsonwebtoken');
const { handleCors } = require('../lib/cors');
const supabase = require('../lib/supabase');

const getDurationMs = (str) => {
  const def = 30 * 24 * 60 * 60 * 1000;
  if (!str || str.toLowerCase() === 'null') return def;
  const m = str.match(/(\d+)\s*(day|hour|minute|second)/i);
  if (!m) return def;
  const map = { day: 86400000, hour: 3600000, minute: 60000, second: 1000 };
  return parseInt(m[1]) * (map[m[2].toLowerCase()] || 86400000);
};

module.exports = async (req, res) => {
  if (handleCors(req, res)) return;
  if (req.method !== 'POST') return res.status(405).end();

  const { email, license_key } = req.body;
  try {
    const { data: lic, error } = await supabase
      .from('licenses').select('*').eq('email', email).eq('license_key', license_key).single();

    if (error || !lic || lic.status === 'revoked')
      return res.status(403).json({ success: false, message: 'Invalid Key' });

    const now = new Date();

    if (lic.is_used && lic.expires_at) {
      if (new Date(lic.expires_at) < now) {
        await supabase.from('licenses').update({ status: 'expired' }).eq('id', lic.id);
        return res.status(403).json({ success: false, message: 'Expired' });
      }
    } else {
      const expiresAt = new Date(now.getTime() + getDurationMs(lic.plan_duration)).toISOString();
      await supabase.from('licenses').update({ is_used: true, expires_at: expiresAt, status: 'active' }).eq('id', lic.id);
      lic.expires_at = expiresAt;
    }

    // ✅ JWT expiry matches actual license duration
    const expiresIn = Math.floor((new Date(lic.expires_at) - now) / 1000);
    const token = jwt.sign(
      { id: lic.id, email: lic.email, authType: 'license' },
      process.env.JWT_SECRET,
      { expiresIn: `${expiresIn}s` }
    );
    res.json({ success: true, token });
  } catch {
    res.status(500).json({ success: false });
  }
};

const crypto = require('crypto');
const { handleCors } = require('../lib/cors');
const supabase = require('../lib/supabase');

const safeCompare = (input, secret) => {
  if (!input || !secret) return false;
  const a = Buffer.from(input), b = Buffer.from(secret);
  if (a.length !== b.length) return false;
  return crypto.timingSafeEqual(a, b);
};

const generateKey = () => {
  const p1 = crypto.randomBytes(3).toString('hex').toUpperCase();
  const p2 = crypto.randomBytes(3).toString('hex').toUpperCase();
  return `PRO-${p1}-${p2}`;
};

module.exports = async (req, res) => {
  if (handleCors(req, res)) return;
  if (req.method !== 'POST') return res.status(405).end();

  const { email, plan_duration, admin_secret } = req.body;
  if (!safeCompare(admin_secret, process.env.ADMIN_SECRET))
    return res.status(401).json({ success: false });

  const { data } = await supabase.from('licenses').insert([{
    email,
    license_key: generateKey(),
    plan_duration: plan_duration || '30 days',
    status: 'active',
    is_used: false,
  }]).select().single();

  res.json({ success: true, license: data });
};

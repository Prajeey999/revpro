const { supabase, safeCompare, generateSecureKey, setCors, ADMIN_SECRET } = require("./_helpers");

module.exports = async (req, res) => {
  setCors(req, res);
  if (req.method === "OPTIONS") return res.status(200).end();

  const { email, plan_duration, admin_secret } = req.body;
  if (!safeCompare(admin_secret, ADMIN_SECRET)) {
    return res.status(401).json({ success: false });
  }

  const key = generateSecureKey();
  const { data } = await supabase
    .from("licenses")
    .insert([{ email, license_key: key, plan_duration: plan_duration || "30 days", status: "active", is_used: false }])
    .select().single();

  res.json({ success: true, license: data });
};
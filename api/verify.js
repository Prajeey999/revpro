const jwt = require("jsonwebtoken");
const { supabase, setCors, getDurationMs } = require("./_helpers");

module.exports = async (req, res) => {
  setCors(req, res);
  if (req.method === "OPTIONS") return res.status(200).end();

  const { email, license_key } = req.body;
  try {
    const { data: lic, error } = await supabase
      .from("licenses").select("*")
      .eq("email", email).eq("license_key", license_key).single();

    if (error || !lic || lic.status === "revoked")
      return res.status(403).json({ success: false, message: "Invalid Key" });

    const now = new Date();
    if (lic.is_used && lic.expires_at) {
      if (new Date(lic.expires_at) < now) {
        await supabase.from("licenses").update({ status: "expired" }).eq("id", lic.id);
        return res.status(403).json({ success: false, message: "Expired" });
      }
    } else {
      const ms = getDurationMs(lic.plan_duration);
      const { data: updated } = await supabase
        .from("licenses")
        .update({ is_used: true, expires_at: new Date(now.getTime() + ms).toISOString(), status: "active" })
        .eq("id", lic.id).select().single();
      lic.id = updated.id;
      lic.email = updated.email;
    }

    const token = jwt.sign(
      { id: lic.id, email: lic.email, authType: "license" },
      process.env.JWT_SECRET,
      { expiresIn: "24h" }
    );
    res.json({ success: true, token });
  } catch (e) {
    res.status(500).json({ success: false });
  }
};
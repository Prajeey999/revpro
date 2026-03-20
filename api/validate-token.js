if (decoded.authType === "patreon") {
  const userAccessToken = await getPatreonToken(decoded.id);
  console.log("patreon id:", decoded.id);
  console.log("has token:", !!userAccessToken);
  
  if (!userAccessToken) return res.status(401).json({ valid: false, reason: "no_patreon_token" });

  const live = await axios.get(
    "https://www.patreon.com/api/oauth2/v2/identity?include=memberships.currently_entitled_tiers&fields[member]=patron_status",
    { headers: { Authorization: `Bearer ${userAccessToken}` } }
  );

  console.log("patreon memberships:", JSON.stringify(live.data.included));
  console.log("REQUIRED_TIER_ID:", process.env.PATREON_REQUIRED_TIER_ID);

  const creatorId = await getCreatorId();
  console.log("creatorId:", creatorId);
  console.log("patId:", live.data.data.id);
  
  const active = checkMembership(live.data, creatorId);
  console.log("active:", active);
  
  return active ? res.json({ valid: true }) : res.status(401).json({ valid: false, reason: "not_active_patron" });
}
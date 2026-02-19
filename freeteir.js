require("dotenv").config();
const axios = require("axios");

async function getFreeTierId() {
  const ACCESS_TOKEN = process.env.PATREON_CREATOR_ACCESS_TOKEN;

  try {
    // Request tiers explicitly with title and amount_cents
    const campaignRes = await axios.get(
      "https://www.patreon.com/api/oauth2/v2/campaigns?include=tiers&fields[tier]=title,amount_cents",
      { headers: { Authorization: `Bearer ${ACCESS_TOKEN}` } }
    );

    const campaign = campaignRes.data.data[0];
    const included = campaignRes.data.included || [];

    console.log("Campaign ID:", campaign.id);

    // Only tiers
    const tiers = included.filter(i => i.type === "tier");
    console.log("All tiers:");
    tiers.forEach(t => {
      console.log(`Name: ${t.attributes.title} | ID: ${t.id} | Amount: ${t.attributes.amount_cents}`);
    });

    const freeTier = tiers.find(t => t.attributes.amount_cents === 0);
    if (freeTier) {
      console.log("✅ Free Tier ID:", freeTier.id);
    } else {
      console.log("No Free Tier found for this campaign.");
    }

  } catch (err) {
    console.error(err.response?.data || err.message);
  }
}

getFreeTierId();

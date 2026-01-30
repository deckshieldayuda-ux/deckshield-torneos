import crypto from "crypto";

function verifyShopifyProxy(query) {
  const { signature, ...rest } = query;

  if (!signature) return false;

  const message = Object.keys(rest)
    .sort()
    .map((key) => `${key}=${rest[key]}`)
    .join("");

  const generatedSignature = crypto
    .createHmac("sha256", process.env.SHOPIFY_APP_PROXY_SECRET)
    .update(message)
    .digest("hex");

  return generatedSignature === signature;
}

export default function handler(req, res) {
  const isValid = verifyShopifyProxy(req.query);

  if (!isValid) {
    return res.status(401).json({
      ok: false,
      error: "Invalid Shopify signature",
    });
  }

  const customerId = req.query.logged_in_customer_id || null;

  if (!customerId) {
    return res.status(200).json({
      ok: true,
      logged_in: false,
    });
  }

  res.status(200).json({
    ok: true,
    logged_in: true,
    customer_id: customerId,
  });
}

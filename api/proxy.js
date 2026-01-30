export default function handler(req, res) {
  const safeHeaders = {
    host: req.headers.host,
    "user-agent": req.headers["user-agent"],
    referer: req.headers.referer,
    "x-forwarded-for": req.headers["x-forwarded-for"],
    "x-shopify-shop-domain": req.headers["x-shopify-shop-domain"],
    "x-shopify-customer-id": req.headers["x-shopify-customer-id"],
    "x-shopify-logged-in": req.headers["x-shopify-logged-in"],
  };

  res.status(200).json({
    ok: true,
    source: "shopify-app-proxy",
    method: req.method,
    query: req.query || {},
    headers: safeHeaders,
  });
}

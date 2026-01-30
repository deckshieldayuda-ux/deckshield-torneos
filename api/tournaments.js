import crypto from "crypto";
import { supabase } from "./_lib/supabase.js";

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

export default async function handler(req, res) {
  // Solo GET por ahora
  if (req.method !== "GET") {
    return res.status(405).json({ ok: false, error: "Method not allowed" });
  }

  // Verificar que venga de Shopify
  const isValid = verifyShopifyProxy(req.query);
  if (!isValid) {
    return res.status(401).json({ ok: false, error: "Invalid Shopify signature" });
  }

  const customerId = req.query.logged_in_customer_id;
  if (!customerId) {
    return res.status(200).json({
      ok: true,
      tournaments: [],
    });
  }

  // Consultar Supabase
  const { data, error } = await supabase
    .from("tournaments")
    .select("*")
    .eq("customer_id", customerId)
    .order("tournament_date", { ascending: false });

  if (error) {
    return res.status(500).json({
      ok: false,
      error: "Database error",
    });
  }

  return res.status(200).json({
    ok: true,
    tournaments: data,
  });
}

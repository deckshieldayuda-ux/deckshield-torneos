import crypto from "crypto";
import { supabase } from "./_lib/supabase.js";

/* =========================
   Shopify App Proxy Verify
========================= */
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

/* =========================
   Actions
========================= */
async function listTournaments(customerId) {
  const { data, error } = await supabase
    .from("tournaments")
    .select("*")
    .eq("customer_id", customerId)
    .order("tournament_date", { ascending: false });

  if (error) {
    throw new Error("Database error");
  }

  return data;
}

/* =========================
   Main Handler
========================= */
export default async function handler(req, res) {
  // 1️⃣ Verificar Shopify
  const isValid = verifyShopifyProxy(req.query);
  if (!isValid) {
    return res.status(401).json({
      ok: false,
      error: "Invalid Shopify signature",
    });
  }

  // 2️⃣ Identidad
  const customerId = req.query.logged_in_customer_id || null;
  const action = req.query.action || null;

  if (!customerId) {
    return res.status(200).json({
      ok: true,
      logged_in: false,
    });
  }

  // 3️⃣ Router interno
  try {
    switch (action) {
      case "list_tournaments": {
               case "create_tournament": {
        const {
          tournament_name,
          tournament_date,
          format = null,
          tournament_type = null,
          result = null,
        } = req.query;

        // Validación mínima
        if (!tournament_name || !tournament_date) {
          return res.status(400).json({
            ok: false,
            error: "Missing required fields",
          });
        }

        const { data, error } = await supabase
          .from("tournaments")
          .insert([
            {
              customer_id: customerId,
              tournament_name,
              tournament_date,
              format,
              tournament_type,
              result,
            },
          ])
          .select()
          .single();

        if (error) {
          return res.status(500).json({
            ok: false,
            error: "Database insert failed",
          });
        }

        return res.status(200).json({
          ok: true,
          tournament: data,
        });
      }

        const tournaments = await listTournaments(customerId);
        return res.status(200).json({
          ok: true,
          tournaments,
        });
      }

      default:
        return res.status(400).json({
          ok: false,
          error: "Unknown action",
        });
    }
  } catch (err) {
    return res.status(500).json({
      ok: false,
      error: "Internal server error",
    });
  }
}

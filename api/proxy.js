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
    console.error("Supabase list error:", error);
    throw new Error(error.message || "Database error");
  }

  return data ?? [];
}

async function createTournament(customerId, query) {
  const {
    tournament_name,
    tournament_date,
    format = null,
    tournament_type = null,
    result = null,
  } = query;

  // Validación mínima
  if (!tournament_name || !tournament_date) {
    return {
      ok: false,
      error: "Missing required fields",
      fields_required: ["tournament_name", "tournament_date"],
    };
  }

  // Insert sin rondas/score desde el frontend
  const payload = {
    customer_id: customerId,
    tournament_name,
    tournament_date,
    format,
    tournament_type,
    result,
    // opcional: inicializar explícitamente si tu tabla no tiene default
    rounds: [],
    score: {},
  };

  const { data, error } = await supabase
    .from("tournaments")
    .insert([payload])
    .select("*")
    .single();

  if (error) {
    console.error("Supabase insert error:", error);
    return {
      ok: false,
      error: "Database insert failed",
      details: error.message,
    };
  }

  return { ok: true, tournament: data };
}

/* =========================
   Main Handler
========================= */
export default async function handler(req, res) {
  // Shopify App Proxy suele llamar por GET; dejamos todo por query por ahora.
  // IMPORTANTE: Para Shopify, evitamos 500 para no mostrar pantalla genérica.

  // 1️⃣ Verificar Shopify
  const isValid = verifyShopifyProxy(req.query);
  if (!isValid) {
    // Esto sí puede ser 401 porque ocurre fuera de Shopify normal
    // pero si prefieres evitar pantallas, cámbialo a 200 también.
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
        const tournaments = await listTournaments(customerId);
        return res.status(200).json({
          ok: true,
          tournaments,
        });
      }

      case "create_tournament": {
        const result = await createTournament(customerId, req.query);
        // Siempre 200 para que Shopify muestre JSON y no pantalla genérica
        return res.status(200).json(result);
      }

      default:
        return res.status(200).json({
          ok: false,
          error: "Unknown action",
          allowed_actions: ["list_tournaments", "create_tournament"],
        });
    }
  } catch (err) {
    console.error("Proxy handler error:", err);
    return res.status(200).json({
      ok: false,
      error: "Internal error",
      details: err?.message || String(err),
    });
  }
}

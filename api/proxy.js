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

  if (!tournament_name || !tournament_date) {
    return {
      ok: false,
      error: "Missing required fields",
      fields_required: ["tournament_name", "tournament_date"],
    };
  }

  const payload = {
    customer_id: customerId,
    tournament_name,
    tournament_date,
    format,
    tournament_type,
    result,
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

async function getTournament(customerId, id) {
  if (!id) return { ok: false, error: "Missing id" };

  const { data, error } = await supabase
    .from("tournaments")
    .select("*")
    .eq("id", id)
    .eq("customer_id", customerId)
    .single();

  if (error) {
    console.error("Supabase get error:", error);
    return { ok: false, error: "Tournament not found" };
  }

  return { ok: true, tournament: data };
}

async function updateTournament(customerId, id, query) {
  if (!id) return { ok: false, error: "Missing id" };

  // Solo permitimos editar estos campos del torneo "meta"
  const allowed = [
    "tournament_name",
    "tournament_date",
    "format",
    "tournament_type",
    "result",
  ];

  const updates = {};
  for (const key of allowed) {
    if (query[key] !== undefined) updates[key] = query[key];
  }

  if (Object.keys(updates).length === 0) {
    return { ok: false, error: "No fields to update" };
  }

  const { data, error } = await supabase
    .from("tournaments")
    .update(updates)
    .eq("id", id)
    .eq("customer_id", customerId)
    .select("*")
    .single();

  if (error) {
    console.error("Supabase update error:", error);
    return { ok: false, error: "Update failed", details: error.message };
  }

  return { ok: true, tournament: data };
}

/* =========================
   Main Handler
========================= */
export default async function handler(req, res) {
  // 1) Verificar Shopify App Proxy
  const isValid = verifyShopifyProxy(req.query);
  if (!isValid) {
    // 401 está bien aquí; si prefieres evitar cualquier pantalla, cambia a 200
    return res.status(401).json({
      ok: false,
      error: "Invalid Shopify signature",
    });
  }

  // 2) Identidad + acción
  const customerId = req.query.logged_in_customer_id || null;
  const action = req.query.action || null;

  if (!customerId) {
    return res.status(200).json({
      ok: true,
      logged_in: false,
    });
  }

  // 3) Router interno
  try {
    switch (action) {
      case "list_tournaments": {
        const tournaments = await listTournaments(customerId);
        return res.status(200).json({ ok: true, tournaments });
      }

      case "create_tournament": {
        const result = await createTournament(customerId, req.query);
        return res.status(200).json(result);
      }

      case "get_tournament": {
        const result = await getTournament(customerId, req.query.id);
        return res.status(200).json(result);
      }

      case "update_tournament": {
        const result = await updateTournament(customerId, req.query.id, req.query);
        return res.status(200).json(result);
      }

      default:
        return res.status(200).json({
          ok: false,
          error: "Unknown action",
          allowed_actions: [
            "list_tournaments",
            "create_tournament",
            "get_tournament",
            "update_tournament",
          ],
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

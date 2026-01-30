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
   Helpers
========================= */
function toIntOrNull(v) {
  if (v === undefined || v === null || v === "") return null;
  const n = Number(v);
  return Number.isFinite(n) ? n : null;
}

function normalizeResult(v) {
  if (v === undefined) return undefined; // no tocar
  if (v === null || v === "" || v === "null") return null;

  const up = String(v).toUpperCase();
  if (up === "W" || up === "L" || up === "T") return up;
  return undefined; // inválido
}

function normalizeTurn(v) {
  if (v === undefined) return undefined; // no tocar
  if (v === null || v === "" || v === "null") return null;

  const up = String(v).toUpperCase();
  if (up === "FIRST" || up === "SECOND") return up;
  return undefined;
}

function normalizeSpecial(v) {
  if (v === undefined) return undefined; // no tocar
  if (v === null || v === "" || v === "null") return null;

  const up = String(v).toUpperCase();
  if (up === "ID" || up === "NO_SHOW" || up === "BYE") return up;
  return undefined;
}

async function getTournamentOwned(customerId, tournamentId) {
  if (!tournamentId) {
    return { ok: false, error: "Missing tournament id" };
  }

  const { data, error } = await supabase
    .from("tournaments")
    .select("*")
    .eq("id", tournamentId)
    .eq("customer_id", customerId)
    .single();

  if (error) {
    console.error("Supabase getTournamentOwned error:", error);
    return { ok: false, error: "Tournament not found" };
  }

  return { ok: true, tournament: data };
}

async function saveRounds(customerId, tournamentId, rounds) {
  const { data, error } = await supabase
    .from("tournaments")
    .update({ rounds })
    .eq("id", tournamentId)
    .eq("customer_id", customerId)
    .select("*")
    .single();

  if (error) {
    console.error("Supabase saveRounds error:", error);
    return { ok: false, error: "Failed to save rounds", details: error.message };
  }

  return { ok: true, tournament: data };
}

/* =========================
   Actions (existing)
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
  return await getTournamentOwned(customerId, id);
}

async function updateTournament(customerId, id, query) {
  if (!id) return { ok: false, error: "Missing id" };

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
   Actions (Rounds)
========================= */
async function addRound(customerId, tournamentId) {
  const got = await getTournamentOwned(customerId, tournamentId);
  if (!got.ok) return got;

  const tournament = got.tournament;
  const rounds = Array.isArray(tournament.rounds) ? tournament.rounds : [];

  const maxRound = rounds.reduce((m, r) => {
    const n = Number(r?.round_number);
    return Number.isFinite(n) ? Math.max(m, n) : m;
  }, 0);

  const newRoundNumber = maxRound + 1;

  const newRound = {
    round_number: newRoundNumber,
    opponent_deck: { p1: null, p2: null },
    games: [
      { game: 1, result: null, turn: null },
      { game: 2, result: null, turn: null },
      { game: 3, result: null, turn: null },
    ],
    special: null, // "ID" | "NO_SHOW" | "BYE" | null
  };

  rounds.push(newRound);

  return await saveRounds(customerId, tournamentId, rounds);
}

async function updateRound(customerId, tournamentId, query) {
  const roundNumber = toIntOrNull(query.round_number);
  if (!tournamentId) return { ok: false, error: "Missing tournament id" };
  if (!roundNumber) return { ok: false, error: "Missing or invalid round_number" };

  const got = await getTournamentOwned(customerId, tournamentId);
  if (!got.ok) return got;

  const tournament = got.tournament;
  const rounds = Array.isArray(tournament.rounds) ? tournament.rounds : [];

  const idx = rounds.findIndex((r) => Number(r?.round_number) === roundNumber);
  if (idx === -1) return { ok: false, error: "Round not found" };

  const round = rounds[idx];

  // Opponent deck (optional)
  const opP1 = toIntOrNull(query.op_p1);
  const opP2 = toIntOrNull(query.op_p2);
  if (query.op_p1 !== undefined || query.op_p2 !== undefined) {
    round.opponent_deck = round.opponent_deck || { p1: null, p2: null };
    if (query.op_p1 !== undefined) round.opponent_deck.p1 = opP1;
    if (query.op_p2 !== undefined) round.opponent_deck.p2 = opP2;
  }

  // Special (optional)
  const sp = normalizeSpecial(query.special);
  if (query.special !== undefined) {
    if (sp === undefined) return { ok: false, error: "Invalid special value" };
    round.special = sp;
  }

  // Games (optional)
  round.games = Array.isArray(round.games)
    ? round.games
    : [
        { game: 1, result: null, turn: null },
        { game: 2, result: null, turn: null },
        { game: 3, result: null, turn: null },
      ];

  const g1 = normalizeResult(query.g1);
  const g2 = normalizeResult(query.g2);
  const g3 = normalizeResult(query.g3);
  if (query.g1 !== undefined && g1 === undefined) return { ok: false, error: "Invalid g1 value" };
  if (query.g2 !== undefined && g2 === undefined) return { ok: false, error: "Invalid g2 value" };
  if (query.g3 !== undefined && g3 === undefined) return { ok: false, error: "Invalid g3 value" };

  const g1t = normalizeTurn(query.g1_turn);
  const g2t = normalizeTurn(query.g2_turn);
  const g3t = normalizeTurn(query.g3_turn);
  if (query.g1_turn !== undefined && g1t === undefined) return { ok: false, error: "Invalid g1_turn value" };
  if (query.g2_turn !== undefined && g2t === undefined) return { ok: false, error: "Invalid g2_turn value" };
  if (query.g3_turn !== undefined && g3t === undefined) return { ok: false, error: "Invalid g3_turn value" };

  // apply to game objects by game number
  const byNum = new Map(round.games.map((g) => [Number(g.game), g]));
  const game1 = byNum.get(1) || { game: 1, result: null, turn: null };
  const game2 = byNum.get(2) || { game: 2, result: null, turn: null };
  const game3 = byNum.get(3) || { game: 3, result: null, turn: null };

  if (query.g1 !== undefined) game1.result = g1;
  if (query.g2 !== undefined) game2.result = g2;
  if (query.g3 !== undefined) game3.result = g3;

  if (query.g1_turn !== undefined) game1.turn = g1t;
  if (query.g2_turn !== undefined) game2.turn = g2t;
  if (query.g3_turn !== undefined) game3.turn = g3t;

  round.games = [game1, game2, game3];

  // Persist
  rounds[idx] = round;
  return await saveRounds(customerId, tournamentId, rounds);
}

/* =========================
   Main Handler
========================= */
export default async function handler(req, res) {
  // 1) Verificar Shopify App Proxy
  const isValid = verifyShopifyProxy(req.query);
  if (!isValid) {
    return res.status(401).json({ ok: false, error: "Invalid Shopify signature" });
  }

  // 2) Identidad + acción
  const customerId = req.query.logged_in_customer_id || null;
  const action = req.query.action || null;

  if (!customerId) {
    return res.status(200).json({ ok: true, logged_in: false });
  }

  // 3) Router interno (siempre JSON)
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

      // ---- ROUNDS ----
      case "add_round": {
        const result = await addRound(customerId, req.query.id);
        return res.status(200).json(result);
      }

      case "update_round": {
        const result = await updateRound(customerId, req.query.id, req.query);
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
            "add_round",
            "update_round",
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

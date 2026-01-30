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
  if (v === undefined) return undefined;
  if (v === null || v === "" || v === "null") return null;

  const up = String(v).toUpperCase();
  if (up === "W" || up === "L" || up === "T") return up;
  return undefined;
}

function normalizeTurn(v) {
  if (v === undefined) return undefined;
  if (v === null || v === "" || v === "null") return null;

  const up = String(v).toUpperCase();
  if (up === "FIRST" || up === "SECOND") return up;
  return undefined;
}

function normalizeSpecial(v) {
  if (v === undefined) return undefined;
  if (v === null || v === "" || v === "null") return null;

  const up = String(v).toUpperCase();
  if (up === "ID" || up === "NO_SHOW" || up === "BYE") return up;
  return undefined;
}

/* =========================
   Score + Sanitize
========================= */
function computeScore(rounds) {
  let wins = 0;
  let losses = 0;
  let ties = 0;

  const safeRounds = Array.isArray(rounds) ? rounds : [];

  for (const r of safeRounds) {
    const special = r?.special ?? null;

    if (special === "BYE" || special === "NO_SHOW") {
      wins++;
      continue;
    }
    if (special === "ID") {
      ties++;
      continue;
    }

    const games = Array.isArray(r?.games) ? r.games : [];
    let w = 0, l = 0;
    let hasAny = false;

    for (const g of games) {
      if (!g?.result) continue;
      hasAny = true;
      if (g.result === "W") w++;
      if (g.result === "L") l++;
    }

    if (!hasAny) continue;
    if (w > l) wins++;
    else if (l > w) losses++;
    else ties++;
  }

  return { wins, losses, ties, text: `${wins}-${losses}-${ties}` };
}

function sanitizeRounds(rounds) {
  const safeRounds = Array.isArray(rounds) ? rounds : [];
  return safeRounds.map((r) => {
    const round = { ...r };
    round.opponent_deck = round.opponent_deck || { p1: null, p2: null };

    if (round.special === "BYE" || round.special === "NO_SHOW" || round.special === "ID") {
      round.games = [
        { game: 1, result: null, turn: null },
        { game: 2, result: null, turn: null },
        { game: 3, result: null, turn: null },
      ];
    }

    return round;
  });
}

/* =========================
   DB helpers
========================= */
async function getTournamentOwned(customerId, id) {
  const { data, error } = await supabase
    .from("tournaments")
    .select("*")
    .eq("id", id)
    .eq("customer_id", customerId)
    .single();

  if (error) return { ok: false, error: "Tournament not found" };
  return { ok: true, tournament: data };
}

async function persistRounds(customerId, id, rounds) {
  const clean = sanitizeRounds(rounds);
  const score = computeScore(clean);

  const { data, error } = await supabase
    .from("tournaments")
    .update({ rounds: clean, score })
    .eq("id", id)
    .eq("customer_id", customerId)
    .select("*")
    .single();

  if (error) return { ok: false, error: "Failed to save rounds" };
  return { ok: true, tournament: data };
}

/* =========================
   Actions
========================= */
async function listTournaments(customerId) {
  const { data } = await supabase
    .from("tournaments")
    .select("*")
    .eq("customer_id", customerId)
    .order("tournament_date", { ascending: false });

  return data ?? [];
}

async function createTournament(customerId, q) {
  if (!q.tournament_name || !q.tournament_date) {
    return { ok: false, error: "Missing required fields" };
  }

  const { data, error } = await supabase
    .from("tournaments")
    .insert([{
      customer_id: customerId,
      tournament_name: q.tournament_name,
      tournament_date: q.tournament_date,
      format: q.format ?? null,
      tournament_type: q.tournament_type ?? null,
      result: q.result ?? "SinTop",
      rounds: [],
      score: computeScore([])
    }])
    .select("*")
    .single();

  if (error) return { ok: false, error: "Insert failed" };
  return { ok: true, tournament: data };
}

async function addRound(customerId, id) {
  const got = await getTournamentOwned(customerId, id);
  if (!got.ok) return got;

  const rounds = got.tournament.rounds || [];
  const nextNumber = rounds.length + 1;

  rounds.push({
    round_number: nextNumber,
    opponent_deck: { p1: null, p2: null },
    games: [
      { game: 1, result: null, turn: null },
      { game: 2, result: null, turn: null },
      { game: 3, result: null, turn: null },
    ],
    special: null,
  });

  return await persistRounds(customerId, id, rounds);
}

async function updateRound(customerId, id, q) {
  const rn = toIntOrNull(q.round_number);
  if (!rn) return { ok: false, error: "Invalid round_number" };

  const got = await getTournamentOwned(customerId, id);
  if (!got.ok) return got;

  const rounds = got.tournament.rounds || [];
  const idx = rounds.findIndex(r => r.round_number === rn);
  if (idx === -1) return { ok: false, error: "Round not found" };

  const r = rounds[idx];

  if (q.op_p1 !== undefined) r.opponent_deck.p1 = toIntOrNull(q.op_p1);
  if (q.op_p2 !== undefined) r.opponent_deck.p2 = toIntOrNull(q.op_p2);

  if (q.special !== undefined) r.special = normalizeSpecial(q.special);

  const g1 = normalizeResult(q.g1);
  if (g1 !== undefined) r.games[0].result = g1;

  rounds[idx] = r;
  return await persistRounds(customerId, id, rounds);
}

async function setFinalResult(customerId, id, result) {
  const allowed = [
    "Ganador","Finalista","Top4","Top8","Top16","Top32",
    "Top64","Top128","Top256","Top512","Top1024",
    "Droppeado","SinTop"
  ];

  if (!allowed.includes(result)) {
    return { ok: false, error: "Invalid final result" };
  }

  const { data, error } = await supabase
    .from("tournaments")
    .update({ result })
    .eq("id", id)
    .eq("customer_id", customerId)
    .select("*")
    .single();

  if (error) return { ok: false, error: "Failed to update result" };
  return { ok: true, tournament: data };
}

/* =========================
   Main Handler
========================= */
export default async function handler(req, res) {
  if (!verifyShopifyProxy(req.query)) {
    return res.status(401).json({ ok: false, error: "Invalid Shopify signature" });
  }

  const customerId = req.query.logged_in_customer_id;
  const action = req.query.action;

  if (!customerId) return res.json({ ok: true, logged_in: false });

  switch (action) {
    case "list_tournaments":
      return res.json({ ok: true, tournaments: await listTournaments(customerId) });

    case "create_tournament":
      return res.json(await createTournament(customerId, req.query));

    case "add_round":
      return res.json(await addRound(customerId, req.query.id));

    case "update_round":
      return res.json(await updateRound(customerId, req.query.id, req.query));

    case "set_final_result":
      return res.json(await setFinalResult(customerId, req.query.id, req.query.result));

    default:
      return res.json({ ok: false, error: "Unknown action" });
  }
}

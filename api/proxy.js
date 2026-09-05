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

function normalizeWinCondition(v) {
  if (v === undefined) return undefined;
  if (v === null || v === "" || v === "null") return null;

  const up = String(v).toUpperCase();
  if (up === "PRIZES" || up === "NO_POKEMON" || up === "DECK_OUT") return up;
  return undefined;
}

function normalizeSpecial(v) {
  if (v === undefined) return undefined;
  if (v === null || v === "" || v === "null") return null;

  const up = String(v).toUpperCase();
  if (up === "ID" || up === "NO_SHOW" || up === "BYE" || up === "DROP" || up === "DQ") return up;
  return undefined;
}

// El "componente #2" de un deck puede ser un segundo Pokémon o una carta de
// Entrenador/Ítem clave (ej. Crushing Hammer en un deck de un solo Pokémon).
// undefined = no se tocó este campo; null = se limpió a propósito.
function buildDeckPiece(kind, id, name, image) {
  if (kind === undefined) return undefined;
  if (kind === "item") {
    const cleanName = (name ?? "").toString().trim();
    if (!cleanName) return null;
    return { kind: "item", name: cleanName, image: (image ?? "").toString().trim() || null };
  }
  if (kind === "pokemon") {
    const pid = toIntOrNull(id);
    return pid == null ? null : { kind: "pokemon", id: pid };
  }
  return null;
}

// Drop y Descalificación terminan el torneo: no se pueden agregar más rondas
// y cualquier ronda posterior que ya existiera queda eliminada.
const ENDS_TOURNAMENT = ["DROP", "DQ"];

const EMPTY_GAMES = () => ([
  { game: 1, result: null, turn: null, win_condition: null },
  { game: 2, result: null, turn: null, win_condition: null },
  { game: 3, result: null, turn: null, win_condition: null },
]);

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
    if (ENDS_TOURNAMENT.includes(special)) {
      losses++;
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

    const noOpponent = round.special === "BYE" || round.special === "NO_SHOW";
    if (noOpponent) {
      round.opponent_deck = { p1: null, p2: null };
    }

    const noGames = noOpponent || round.special === "ID" || ENDS_TOURNAMENT.includes(round.special);
    if (noGames) {
      round.games = EMPTY_GAMES();
    } else {
      // Al mejor de 3: si ya hay 2 juegos decididos para el mismo lado, el
      // tercer juego no se juega y no debe contar aunque tenga algo guardado.
      const games = Array.isArray(round.games) && round.games.length === 3
        ? round.games.map(g => ({ ...g }))
        : EMPTY_GAMES();

      const w = games.filter(g => g?.result === "W").length;
      const l = games.filter(g => g?.result === "L").length;
      const tieInFirstTwo = games[0]?.result === "T" || games[1]?.result === "T";
      if (w >= 2 || l >= 2 || tieInFirstTwo) {
        games[2] = { game: 3, result: null, turn: null, win_condition: null };
      }
      round.games = games;
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

async function persistRounds(customerId, id, rounds, extra = {}) {
  const clean = sanitizeRounds(rounds);
  const score = computeScore(clean);

  const { data, error } = await supabase
    .from("tournaments")
    .update({ rounds: clean, score, ...extra })
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

// Clave estable para agrupar un deck (Pokémon #1 + componente #2, que puede ser
// otro Pokémon, una carta de Ítem, o nada) sin importar el formato viejo/nuevo de p2.
function deckKey(deck) {
  if (!deck || deck.p1 == null) return null;
  const p1 = deck.p1;
  const p2 = deck.p2;
  let p2key = "none";
  if (typeof p2 === "number") p2key = "pokemon:" + p2;
  else if (p2 && p2.kind === "pokemon" && p2.id != null) p2key = "pokemon:" + p2.id;
  else if (p2 && p2.kind === "item" && p2.name) p2key = "item:" + p2.name;
  return `${p1}|${p2key}`;
}

// Resultado de UNA ronda (W/L/T), misma lógica que computeScore pero por ronda
// individual en vez de acumulada — se usa para el cálculo del meta de arquetipos.
function roundOutcome(r) {
  const special = r?.special ?? null;
  if (special === "BYE" || special === "NO_SHOW") return "W";
  if (special === "ID") return "T";
  if (ENDS_TOURNAMENT.includes(special)) return "L";

  const games = Array.isArray(r?.games) ? r.games : [];
  let w = 0, l = 0, hasAny = false;
  for (const g of games) {
    if (!g?.result) continue;
    hasAny = true;
    if (g.result === "W") w++;
    if (g.result === "L") l++;
  }
  if (!hasAny) return null;
  if (w > l) return "W";
  if (l > w) return "L";
  return "T";
}

// Meta de arquetipos: top 8 decks por winrate, calculado sobre TODOS los torneos
// de TODOS los usuarios (no filtra por customer_id a propósito). Requiere un
// mínimo de partidas jugadas para no dejar que un torneo suelto distorsione el ranking.
const META_MIN_SAMPLE = 5;

async function getMetaArchetypes() {
  const { data, error } = await supabase
    .from("tournaments")
    .select("my_deck, rounds");

  if (error) return { ok: false, error: "No se pudo calcular el meta" };

  const stats = new Map();

  for (const t of (data || [])) {
    // Solo entran al meta los decks con 2 componentes (Pokémon+Pokémon o
    // Pokémon+carta) — un deck con un solo Pokémon suele ser data incompleta.
    if (t.my_deck?.p2 == null) continue;

    const key = deckKey(t.my_deck);
    if (!key) continue;

    if (!stats.has(key)) {
      stats.set(key, { p1: t.my_deck.p1, p2: t.my_deck.p2 ?? null, wins: 0, losses: 0, ties: 0 });
    }
    const entry = stats.get(key);

    const rounds = Array.isArray(t.rounds) ? t.rounds : [];
    for (const r of rounds) {
      const outcome = roundOutcome(r);
      if (outcome === "W") entry.wins++;
      else if (outcome === "L") entry.losses++;
      else if (outcome === "T") entry.ties++;
    }
  }

  const archetypes = [];
  for (const entry of stats.values()) {
    const total = entry.wins + entry.losses + entry.ties;
    if (total < META_MIN_SAMPLE) continue;
    archetypes.push({
      p1: entry.p1,
      p2: entry.p2,
      wins: entry.wins,
      losses: entry.losses,
      ties: entry.ties,
      total,
      winrate: entry.wins / total
    });
  }

  archetypes.sort((a, b) => b.winrate - a.winrate);
  return { ok: true, archetypes: archetypes.slice(0, 8) };
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
      my_deck: {
        p1: toIntOrNull(q.my_deck_p1),
        p2: buildDeckPiece(q.my_deck_p2_kind, q.my_deck_p2_id, q.my_deck_p2_name, q.my_deck_p2_image) ?? null
      },
      rounds: [],
      score: computeScore([])
    }])
    .select("*")
    .single();

  if (error) return { ok: false, error: "Insert failed" };
  return { ok: true, tournament: data };
}

async function updateTournament(customerId, id, q) {
  if (!q.tournament_name || !q.tournament_date) {
    return { ok: false, error: "Missing required fields" };
  }

  const { data, error } = await supabase
    .from("tournaments")
    .update({
      tournament_name: q.tournament_name,
      tournament_date: q.tournament_date,
      format: q.format ?? null,
      tournament_type: q.tournament_type ?? null,
      my_deck: {
        p1: toIntOrNull(q.my_deck_p1),
        p2: buildDeckPiece(q.my_deck_p2_kind, q.my_deck_p2_id, q.my_deck_p2_name, q.my_deck_p2_image) ?? null
      }
    })
    .eq("id", id)
    .eq("customer_id", customerId)
    .select("*")
    .single();

  if (error) return { ok: false, error: "No se pudo actualizar" };
  return { ok: true, tournament: data };
}

async function addRound(customerId, id) {
  const got = await getTournamentOwned(customerId, id);
  if (!got.ok) return got;

  const rounds = got.tournament.rounds || [];

  if (rounds.some(r => ENDS_TOURNAMENT.includes(r.special))) {
    return { ok: false, error: "No puedes agregar más rondas: el torneo ya terminó (Drop o Descalificación)." };
  }

  const nextNumber = rounds.length + 1;

  rounds.push({
    round_number: nextNumber,
    opponent_deck: { p1: null, p2: null },
    games: EMPTY_GAMES(),
    special: null,
  });

  return await persistRounds(customerId, id, rounds);
}

async function deleteLastRound(customerId, id) {
  const got = await getTournamentOwned(customerId, id);
  if (!got.ok) return got;

  const rounds = got.tournament.rounds || [];
  if (rounds.length === 0) {
    return { ok: false, error: "No hay rondas para eliminar." };
  }

  const maxRoundNumber = Math.max(...rounds.map(r => r.round_number));
  const finalRounds = rounds.filter(r => r.round_number !== maxRoundNumber);

  return await persistRounds(customerId, id, finalRounds);
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
  const op2 = buildDeckPiece(q.op_p2_kind, q.op_p2_id, q.op_p2_name, q.op_p2_image);
  if (op2 !== undefined) r.opponent_deck.p2 = op2;

  if (q.special !== undefined) r.special = normalizeSpecial(q.special);

  if (!Array.isArray(r.games) || r.games.length !== 3) {
    r.games = EMPTY_GAMES();
  }

  const g1 = normalizeResult(q.g1);
  if (g1 !== undefined) r.games[0].result = g1;
  const g1wc = normalizeWinCondition(q.g1_wc);
  if (g1wc !== undefined) r.games[0].win_condition = g1wc;

  const g2 = normalizeResult(q.g2);
  if (g2 !== undefined) r.games[1].result = g2;
  const g2wc = normalizeWinCondition(q.g2_wc);
  if (g2wc !== undefined) r.games[1].win_condition = g2wc;

  const g3 = normalizeResult(q.g3);
  if (g3 !== undefined) r.games[2].result = g3;
  const g3wc = normalizeWinCondition(q.g3_wc);
  if (g3wc !== undefined) r.games[2].win_condition = g3wc;

  rounds[idx] = r;

  let finalRounds = rounds;
  if (ENDS_TOURNAMENT.includes(r.special)) {
    finalRounds = rounds.filter(rr => rr.round_number <= rn);
  }

  const extra = r.special === "DROP" ? { result: "Droppeado" }
    : r.special === "DQ" ? { result: "Descalificado" }
    : {};

  return await persistRounds(customerId, id, finalRounds, extra);
}

async function deleteTournament(customerId, id) {
  const { error } = await supabase
    .from("tournaments")
    .delete()
    .eq("id", id)
    .eq("customer_id", customerId);

  if (error) return { ok: false, error: "No se pudo eliminar" };
  return { ok: true };
}

async function setFinalResult(customerId, id, result) {
  const allowed = [
    "Ganador","Finalista","Top4","Top8","Top16","Top32",
    "Top64","Top128","Top256","Top512","Top1024",
    "Droppeado","Descalificado","SinTop"
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

  if (!customerId) return res.json({ ok: false, logged_in: false, error: "Debes iniciar sesión con tu cuenta de Deck Shield para registrar o ver tus torneos." });

  switch (action) {
    case "get_tournament":
      return res.json(await getTournamentOwned(customerId, req.query.id));

    case "list_tournaments":
      return res.json({ ok: true, tournaments: await listTournaments(customerId) });

    case "get_meta_archetypes":
      return res.json(await getMetaArchetypes());

    case "create_tournament":
      return res.json(await createTournament(customerId, req.query));

    case "update_tournament":
      return res.json(await updateTournament(customerId, req.query.id, req.query));

    case "add_round":
      return res.json(await addRound(customerId, req.query.id));

    case "delete_last_round":
      return res.json(await deleteLastRound(customerId, req.query.id));

    case "update_round":
      return res.json(await updateRound(customerId, req.query.id, req.query));

    case "delete_tournament":
      return res.json(await deleteTournament(customerId, req.query.id));

    case "set_final_result":
      return res.json(await setFinalResult(customerId, req.query.id, req.query.result));

    default:
      return res.json({ ok: false, error: "Unknown action" });
  }
}

import crypto from "crypto";
import { supabase } from "./_lib/supabase.js";

/* =========================
   Shopify App Proxy Verify
========================= */
// Una request firmada capturada una vez (ej. en el historial del navegador,
// o en un log de proxy) no debe poder reenviarse indefinidamente — Shopify
// incluye "timestamp" (epoch segundos) en todo request de App Proxy, así
// que se rechaza cualquiera con más de 90s de antigüedad.
const MAX_TIMESTAMP_SKEW_SECONDS = 90;

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

  const expected = Buffer.from(generatedSignature, "utf8");
  const received = Buffer.from(String(signature), "utf8");
  if (expected.length !== received.length) return false;
  if (!crypto.timingSafeEqual(expected, received)) return false;

  const ts = Number(rest.timestamp);
  if (!Number.isFinite(ts)) return false;
  const skew = Math.abs(Math.floor(Date.now() / 1000) - ts);
  if (skew > MAX_TIMESTAMP_SKEW_SECONDS) return false;

  return true;
}

/* =========================
   CSRF token (anti-forgía)
   ---------------------------------------------------------------------
   El App Proxy de Shopify firma CUALQUIER request que llegue a la ruta de la
   app, sin importar qué la disparó — un <img>/formulario en un sitio externo
   puede lograr que el navegador de una víctima logueada dispare una acción
   real (borrar torneo, editar ronda) sin que ella haga nada en deckshield.cl.
   Este token no reemplaza la firma de Shopify: la complementa. Se deriva
   matemáticamente (HMAC) del customer_id + una ventana de 5 minutos, sin
   necesitar guardar nada en la base de datos. Un atacante puede lograr que
   el navegador de la víctima DISPARE la request que pide el token, pero
   nunca puede LEER la respuesta (el navegador se lo impide, por ser de otro
   sitio) — así que jamás consigue el valor real para adjuntarlo a una
   acción falsificada.
========================= */
const CSRF_WINDOW_MS = 5 * 60 * 1000;

function _csrfWindow(offset = 0) {
  return Math.floor(Date.now() / CSRF_WINDOW_MS) - offset;
}

function computeCsrfToken(customerId, windowIdx) {
  return crypto
    .createHmac("sha256", process.env.SHOPIFY_APP_PROXY_SECRET)
    .update(`csrf:${customerId}:${windowIdx}`)
    .digest("hex");
}

function _tokensMatch(a, b) {
  const bufA = Buffer.from(String(a), "utf8");
  const bufB = Buffer.from(String(b), "utf8");
  return bufA.length === bufB.length && crypto.timingSafeEqual(bufA, bufB);
}

function verifyCsrfToken(customerId, token) {
  if (!token) return false;
  // Acepta la ventana actual y la anterior (holgura de hasta 5-10 min desde
  // que el frontend pidió el token, para no romper una sesión larga).
  return _tokensMatch(token, computeCsrfToken(customerId, _csrfWindow(0)))
      || _tokensMatch(token, computeCsrfToken(customerId, _csrfWindow(1)));
}

/* =========================
   Helpers
========================= */
// Texto libre (nombre de torneo, nombre de carta) llega sin validar desde
// el cliente — el buscador del frontend restringe qué se puede ELEGIR, pero
// nada impedía llamar la API directo con cualquier string. Se recorta el
// largo y se descartan '<'/'>' para que no pueda guardarse markup/script
// que después se muestre sin escapar en alguna pantalla (ej. Meta de
// Arquetipos, que junta datos de todos los usuarios).
function sanitizeText(v, maxLen) {
  const s = (v ?? "").toString().trim().replace(/[<>]/g, "");
  return s.slice(0, maxLen) || null;
}

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

// Coin flip — dato opcional, por eso admite volver a null (a diferencia de
// special/result, acá "no elegido" es un estado normal, no un error).
function normalizeWentFirst(v) {
  if (v === undefined) return undefined;
  if (v === null || v === "" || v === "null") return null;
  if (v === "true" || v === "1") return true;
  if (v === "false" || v === "0") return false;
  return undefined;
}

// Costo de inscripción del torneo, en pesos chilenos enteros (sin decimales).
// undefined = no se tocó este campo; null = "no registrado" (opcional);
// 0 = torneo gratuito; >0 = monto pagado.
function normalizeCost(v) {
  if (v === undefined) return undefined;
  if (v === null || v === "" || v === "null") return null;

  const digits = String(v).replace(/[^\d]/g, "");
  if (!digits) return undefined;

  const n = Number(digits);
  if (!Number.isFinite(n) || n < 0) return undefined;
  return Math.min(Math.round(n), 100000000);
}

// El "componente #2" de un deck puede ser un segundo Pokémon o una carta de
// Entrenador/Ítem clave (ej. Crushing Hammer en un deck de un solo Pokémon).
// undefined = no se tocó este campo; null = se limpió a propósito.
function buildDeckPiece(kind, id, name, image) {
  if (kind === undefined) return undefined;
  if (kind === "item") {
    const cleanName = sanitizeText(name, 60);
    if (!cleanName) return null;
    return { kind: "item", name: cleanName, image: sanitizeText(image, 500) };
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

      // Ojo: solo cuenta el juego 1 y 2 para decidir si el 3 aplica — si contáramos
      // el juego 3 también, un 3° juego recién guardado que decide la ronda (ej.
      // L-W-W) se autoinvalidaría al verse a sí mismo como si fuera de los primeros 2.
      const firstTwo = [games[0]?.result, games[1]?.result];
      const w = firstTwo.filter(r => r === "W").length;
      const l = firstTwo.filter(r => r === "L").length;
      const tieInFirstTwo = firstTwo.includes("T");
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

/* =========================
   Equivalencias de mazos (tabla deck_aliases)
   ---------------------------------------------------------------------
   Algunos mazos se registran con dos nombres para lo mismo (ej. "Lucario /
   Hariyama" cuando en realidad es "Mega Lucario / Hariyama"). Cada fila de
   deck_aliases dice "este mazo (from_deck) cuenta como este otro (to_deck)".
   Solo se usa para CALCULAR estadísticas (meta y tier list); nunca modifica
   lo que cada usuario registró. `until` (opcional): la equivalencia solo vale
   para torneos jugados hasta esa fecha — sirve para "cerrar" una regla si un
   día ese mazo pasa a ser legítimo. Un solo salto: A->B, no cadenas.
   Nunca lanza: si la tabla no existe o falla, simplemente no hay equivalencias.
========================= */
const ALIAS_CACHE_MS = 60 * 1000;
let aliasCache = { at: 0, list: [] };

async function getDeckAliases() {
  const now = Date.now();
  if (now - aliasCache.at < ALIAS_CACHE_MS) return aliasCache.list;
  let list = [];
  try {
    const { data, error } = await supabase
      .from("deck_aliases")
      .select("from_deck, to_deck, until");
    if (!error && Array.isArray(data)) {
      for (const r of data) {
        const fromKey = deckKey(r.from_deck);
        const to = r.to_deck;
        if (!fromKey || !to || to.p1 == null || to.p2 == null) continue;
        list.push({ from: r.from_deck, to: { p1: to.p1, p2: to.p2 }, until: r.until || null, fromKey });
      }
    }
  } catch (e) {
    list = [];
  }
  aliasCache = { at: now, list };
  return list;
}

// Devuelve el mazo "oficial" al que equivale `deck` (o el mismo si no hay regla).
// `date` = fecha del torneo (YYYY-MM-DD); si no se conoce, no se aplica `until`.
function canonicalDeck(deck, date, aliases) {
  if (!deck || deck.p1 == null || !aliases || !aliases.length) return deck;
  const key = deckKey(deck);
  for (const a of aliases) {
    if (a.fromKey !== key) continue;
    if (a.until && date && date > a.until) continue;
    return { p1: a.to.p1, p2: a.to.p2 };
  }
  return deck;
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

// Suma un resultado a las estadísticas de un deck (mío o del rival). Solo
// entran decks con 2 componentes (Pokémon+Pokémon o Pokémon+carta) — un deck
// con un solo Pokémon suele ser data incompleta.
function addArchetypeResult(stats, deck, outcome) {
  if (!outcome || !deck || deck.p1 == null || deck.p2 == null) return;

  const key = deckKey(deck);
  if (!key) return;

  if (!stats.has(key)) {
    stats.set(key, { p1: deck.p1, p2: deck.p2 ?? null, wins: 0, losses: 0, ties: 0 });
  }
  const entry = stats.get(key);
  if (outcome === "W") entry.wins++;
  else if (outcome === "L") entry.losses++;
  else if (outcome === "T") entry.ties++;
}

// Solo entran al meta arquetipos con winrate sobre 40% — bajo eso no aporta
// como sugerencia de deck "fuerte" y solo hace ruido en el buscador/tier list.
const META_MIN_WINRATE = 0.4;

// rangeDays=null trae TODO el histórico (comportamiento original). Filtra
// por tournament_date (fecha en que se jugó, no en que se registró) porque
// la gente suele registrar en lote días después.
async function buildArchetypeStats(rangeDays) {
  let query = supabase.from("tournaments").select("my_deck, rounds, tournament_date");
  if (rangeDays != null) {
    const cutoff = new Date(Date.now() - rangeDays * 86400000).toISOString().slice(0, 10);
    query = query.gte("tournament_date", cutoff);
  }
  const [{ data, error }, aliases] = await Promise.all([query, getDeckAliases()]);
  if (error) return null;

  const stats = new Map();
  for (const t of (data || [])) {
    const rounds = Array.isArray(t.rounds) ? t.rounds : [];
    const myDeck = canonicalDeck(t.my_deck, t.tournament_date, aliases);
    for (const r of rounds) {
      const outcome = roundOutcome(r);
      if (!outcome) continue;

      // Mi deck se acredita con el resultado tal cual lo viví.
      addArchetypeResult(stats, myDeck, outcome);

      // El deck del rival se acredita con el resultado inverso — así un mirror
      // match (mismo deck de ambos lados) no infla el winrate del arquetipo:
      // mi victoria es necesariamente una derrota para ese mismo mazo del otro lado.
      const opponentOutcome = outcome === "W" ? "L" : outcome === "L" ? "W" : "T";
      addArchetypeResult(stats, canonicalDeck(r.opponent_deck, t.tournament_date, aliases), opponentOutcome);
    }
  }
  return stats;
}

function archetypesFromStats(stats, limit, minSample = META_MIN_SAMPLE) {
  const archetypes = [];
  for (const entry of stats.values()) {
    const total = entry.wins + entry.losses + entry.ties;
    if (total < minSample) continue;
    // Winrate = victorias / (victorias + derrotas) — los empates quedan
    // fuera del cálculo (no cuentan ni a favor ni en contra), a diferencia
    // de `total` (que sí los incluye, como tamaño de muestra real).
    const decisivas = entry.wins + entry.losses;
    const winrate = decisivas > 0 ? entry.wins / decisivas : 0;
    if (winrate <= META_MIN_WINRATE) continue;
    archetypes.push({
      p1: entry.p1,
      p2: entry.p2,
      wins: entry.wins,
      losses: entry.losses,
      ties: entry.ties,
      total,
      winrate
    });
  }
  archetypes.sort((a, b) => b.winrate - a.winrate);
  return archetypes.slice(0, limit);
}

async function getMetaArchetypes() {
  const stats = await buildArchetypeStats(null);
  if (!stats) return { ok: false, error: "No se pudo calcular el meta" };
  return { ok: true, archetypes: archetypesFromStats(stats, 8) };
}

// Tier list "Meta Local": mismos datos, agrupados por banda de winrate en
// vez de un ranking plano, con filtro de ventana de tiempo opcional.
// Cortes calibrados contra convención real de tier lists competitivos de
// TCG (S ~60%+, A ~52-59%, B ~45-51%, C ~40-44%) — no son un invento propio.
function tierFor(winrate) {
  const pct = winrate * 100;
  if (pct >= 60) return "S";
  if (pct >= 52) return "A";
  if (pct >= 45) return "B";
  return "C";
}

const META_RANGE_DAYS = { today: 1, "3d": 3, "7d": 7, "30d": 30 };

// Partidas mínimas para figurar en cada tier: un mazo con buen winrate pero
// pocas partidas no puede estar arriba — baja al tier más alto cuyo mínimo sí
// cumple (S: 40 · A: 30 · B: 15 · C: 10). Bajo 10 partidas no aparece.
const TIER_ORDER = ["S", "A", "B", "C"];
const TIER_MIN_SAMPLE = { S: 40, A: 30, B: 15, C: 10 };

function tierWithSample(winrate, total) {
  for (let i = TIER_ORDER.indexOf(tierFor(winrate)); i < TIER_ORDER.length; i++) {
    if (total >= TIER_MIN_SAMPLE[TIER_ORDER[i]]) return TIER_ORDER[i];
  }
  return null;
}

async function getMetaTierList(range) {
  const rangeDays = META_RANGE_DAYS[range] ?? null;
  const stats = await buildArchetypeStats(rangeDays);
  if (!stats) return { ok: false, error: "No se pudo calcular el meta" };
  const archetypes = archetypesFromStats(stats, Infinity, TIER_MIN_SAMPLE.C)
    .map(a => ({ ...a, tier: tierWithSample(a.winrate, a.total) }))
    .filter(a => a.tier)
    .sort((a, b) => TIER_ORDER.indexOf(a.tier) - TIER_ORDER.indexOf(b.tier) || b.winrate - a.winrate || b.total - a.total)
    .slice(0, 30);
  return { ok: true, archetypes, range: range || "all", min_sample: TIER_MIN_SAMPLE.C };
}

async function createTournament(customerId, q) {
  if (!q.tournament_name || !q.tournament_date) {
    return { ok: false, error: "Missing required fields" };
  }

  const cost = normalizeCost(q.cost);

  const { data, error } = await supabase
    .from("tournaments")
    .insert([{
      customer_id: customerId,
      ...(cost != null ? { cost } : {}),
      tournament_name: sanitizeText(q.tournament_name, 80),
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

  const cost = normalizeCost(q.cost);

  const { data, error } = await supabase
    .from("tournaments")
    .update({
      ...(cost !== undefined ? { cost } : {}),
      tournament_name: sanitizeText(q.tournament_name, 80),
      tournament_date: q.tournament_date,
      format: q.format ?? null,
      tournament_type: q.tournament_type ?? null,
      result: q.result ?? "SinTop",
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

// Intercambia una ronda con la anterior/siguiente. Solo cambia round_number
// (el resto del contenido viaja con la ronda), así el orden de la lista se
// reordena sin tener que editar/eliminar rondas manualmente.
async function moveRound(customerId, id, roundNumber, direction) {
  const rn = toIntOrNull(roundNumber);
  if (!rn) return { ok: false, error: "Invalid round_number" };
  if (direction !== "up" && direction !== "down") {
    return { ok: false, error: "Invalid direction" };
  }

  const got = await getTournamentOwned(customerId, id);
  if (!got.ok) return got;

  const rounds = got.tournament.rounds || [];

  if (rounds.some(r => ENDS_TOURNAMENT.includes(r.special))) {
    return { ok: false, error: "No puedes reordenar rondas: el torneo ya terminó (Drop o Descalificación)." };
  }

  const idx = rounds.findIndex(r => r.round_number === rn);
  if (idx === -1) return { ok: false, error: "Round not found" };

  const targetIdx = direction === "up" ? idx - 1 : idx + 1;
  if (targetIdx < 0 || targetIdx >= rounds.length) {
    return { ok: false, error: "No se puede mover más en esa dirección" };
  }

  const a = rounds[idx];
  const b = rounds[targetIdx];
  const aNum = a.round_number;
  const bNum = b.round_number;
  rounds[idx] = { ...b, round_number: aNum };
  rounds[targetIdx] = { ...a, round_number: bNum };

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
  const op2 = buildDeckPiece(q.op_p2_kind, q.op_p2_id, q.op_p2_name, q.op_p2_image);
  if (op2 !== undefined) r.opponent_deck.p2 = op2;

  if (q.special !== undefined) r.special = normalizeSpecial(q.special);

  const wentFirst = normalizeWentFirst(q.went_first);
  if (wentFirst !== undefined) r.went_first = wentFirst;

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

  const saved = await persistRounds(customerId, id, finalRounds, extra);
  if (!saved.ok) return saved;

  // Independientes entre sí (mazo vs. volumen/resultado) — cuando Drop/DQ
  // dispara los dos a la vez, van en paralelo en vez de uno tras otro.
  const outcome = roundOutcome(r);
  const [deckUnlocked, resultUnlocked] = await Promise.all([
    outcome ? checkDeckAchievements(customerId, saved.tournament.my_deck, outcome, r.opponent_deck) : Promise.resolve([]),
    // Drop/DQ fija un resultado final acá mismo (no pasa por setFinalResult),
    // así que también hay que revisar logros de volumen/resultado en ese caso.
    extra.result ? checkResultAchievements(customerId, saved.tournament) : Promise.resolve([]),
  ]);
  saved.unlocked = [...deckUnlocked, ...resultUnlocked];
  return saved;
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
  const unlocked = await checkResultAchievements(customerId, data);
  return { ok: true, tournament: data, unlocked };
}

/* =========================
   Logros / Hitos
   ---------------------------------------------------------------------
   Se disparan en dos momentos nada más:
   - setFinalResult (y el cierre automático por Drop/DQ dentro de
     updateRound, que también fija un resultado final): volumen de
     torneos CON resultado guardado + logros de resultado. Se eligió
     "resultado guardado" en vez de "torneo creado" para no contar
     torneos abandonados a medio registrar.
   - updateRound, cuando la ronda recién guardada ya tiene un resultado
     determinable (W/L/T): maestría de mazo.

   user_achievements tiene una restricción UNIQUE(customer_id,
   achievement_key) — intentarDesbloquear() aprovecha eso: intenta
   insertar y, si Postgres rechaza por duplicado, simplemente no se
   vuelve a mostrar. No hay que llevar el estado a mano en ningún lado.
========================= */
const VOLUME_THRESHOLDS = [1, 3, 5, 10, 25, 50];
const VOLUME_MESSAGES = {
  3: { icon: "📈", color: "#3A2F1F", title: "3 torneos registrados",
    msg: "¿Sabías que puedes ver qué se está jugando ahora mismo en el meta y con qué winrate? Está en \"Arquetipos Meta\"." },
  5: { icon: "📊", color: "#332A1C", title: "5 torneos registrados",
    msg: "5 torneos ya es data real. Revisa cuál es tu mejor mazo hasta ahora en \"Mis Estadísticas\"." },
  10: { icon: "📊", color: "#2C2318", title: "10 torneos registrados",
    msg: "Ya tienes una temporada completa de datos tuyos. Mira cómo se compara tu winrate con el meta general en \"Arquetipos Meta\"." },
  25: { icon: "🗂️", color: "#1C1710", title: "25 torneos registrados",
    msg: "Esa es una historia completa de tu juego — de tu primer torneo a hoy, todo queda registrado." },
  50: { icon: "🙌", color: "#141210", title: "50 torneos registrados",
    msg: "Gracias por construir esto con nosotros desde el principio — tu historial ya es parte de la comunidad de Deck Shield." },
};

const RESULT_RANK = {
  Ganador: 1, Finalista: 2, Top4: 3, Top8: 4, Top16: 5, Top32: 6,
  Top64: 7, Top128: 8, Top256: 9, Top512: 10, Top1024: 11,
};
const BIG_EVENTS = ["Regional", "Internacional", "Mundial"];

async function intentarDesbloquear(customerId, achievementKey) {
  const { error } = await supabase
    .from("user_achievements")
    .insert([{ customer_id: customerId, achievement_key: achievementKey }]);
  return !error;
}

async function checkResultAchievements(customerId, tournament) {
  const unlocked = [];

  const { data } = await supabase
    .from("tournaments")
    .select("tournament_type, result")
    .eq("customer_id", customerId)
    .neq("result", "SinTop");
  const torneos = data || [];
  const total = torneos.length;

  if (VOLUME_THRESHOLDS.includes(total)) {
    if (total === 1) {
      const { data: compra } = await supabase
        .from("customer_purchase_info")
        .select("total_orders")
        .eq("customer_id", customerId)
        .maybeSingle();
      const esComprador = (compra?.total_orders ?? 0) > 0;
      if (await intentarDesbloquear(customerId, "vol_1")) {
        unlocked.push(esComprador
          ? { key: "vol_1", icon: "🎉", color: "#3A2F1F", title: "¡Primer torneo registrado!",
              msg: "Gracias por confiar en Deck Shield tanto en tus compras como ahora en tu juego — no solo te protegemos las cartas, también te acompañamos en el camino competitivo." }
          : { key: "vol_1", icon: "🎉", color: "#3A2F1F", title: "¡Primer torneo registrado!",
              msg: "Desde ahora Deck Shield lleva la cuenta por ti — mira tu resultado en \"Mis Estadísticas\"." });
      }
    } else {
      const m = VOLUME_MESSAGES[total];
      if (m && await intentarDesbloquear(customerId, `vol_${total}`)) {
        unlocked.push({ key: `vol_${total}`, ...m });
      }
    }
  }

  const tipo = tournament.tournament_type;
  const resultado = tournament.result;

  if (resultado === "Ganador") {
    if (tipo === "Challenge") {
      const veces = torneos.filter(t => t.tournament_type === "Challenge" && t.result === "Ganador").length;
      if (veces === 1 && await intentarDesbloquear(customerId, "logro_primer_challenge")) {
        unlocked.push({ key: "logro_primer_challenge", icon: "🏆", color: "#332A1C", title: "Challenge ganado",
          msg: "Quedó registrada tu primera victoria en un Challenge dentro de Deck Shield." });
      }
    } else if (tipo === "Cup") {
      const veces = torneos.filter(t => t.tournament_type === "Cup" && t.result === "Ganador").length;
      if (veces === 1 && await intentarDesbloquear(customerId, "logro_primer_cup")) {
        unlocked.push({ key: "logro_primer_cup", icon: "🏆", color: "#2C2318", title: "Cup ganado",
          msg: "Quedó registrada tu primera victoria en un Cup dentro de Deck Shield." });
      }
    } else if (!BIG_EVENTS.includes(tipo)) {
      // Genérico solo para Liga/Testeo/sin tipo — Regional/Internacional/Mundial
      // ya quedan cubiertos abajo con un mensaje más específico.
      const veces = torneos.filter(t => t.result === "Ganador").length;
      if (veces === 1 && await intentarDesbloquear(customerId, "logro_primera_victoria")) {
        unlocked.push({ key: "logro_primera_victoria", icon: "🏆", color: "#3A2F1F", title: "¡Torneo ganado!",
          msg: "Registraste tu primer torneo ganado en Deck Shield. Sea tu primer título o el número 50, desde ahora queda guardado acá." });
      }
    }
  }

  if (BIG_EVENTS.includes(tipo)) {
    const vecesEsteTipo = torneos.filter(t => t.tournament_type === tipo).length;
    if (vecesEsteTipo === 1 && await intentarDesbloquear(customerId, `logro_primer_${tipo.toLowerCase()}`)) {
      unlocked.push({ key: `logro_primer_${tipo.toLowerCase()}`, icon: "🚩", color: "#241D14", title: "Nuevo nivel",
        msg: `Registraste tu primer ${tipo} en Deck Shield. Quedará guardado en tu historial acá desde ahora.` });
    }

    const rank = RESULT_RANK[resultado];
    if (rank != null && rank <= 4) {
      const vecesTopGrande = torneos.filter(t =>
        BIG_EVENTS.includes(t.tournament_type) && RESULT_RANK[t.result] != null && RESULT_RANK[t.result] <= 4
      ).length;
      if (vecesTopGrande === 1 && await intentarDesbloquear(customerId, "logro_top_grande")) {
        const etiqueta = resultado === "Ganador" ? "Ganaste" : `Top ${resultado.replace("Top", "")} en`;
        unlocked.push({ key: "logro_top_grande", icon: "⭐", color: "#141210", title: "Gran resultado",
          msg: `${etiqueta} un ${tipo}, registrado en Deck Shield — un resultado que vale la pena tener guardado.` });
      }
    }
  }

  return unlocked;
}

async function checkDeckAchievements(customerId, myDeck, thisRoundOutcome, thisRoundOpponentDeck) {
  const unlocked = [];
  const key = deckKey(myDeck);
  if (!key) return unlocked;

  // Las dos consultas de acá abajo no dependen una de la otra — van en
  // paralelo (Promise.all) en vez de una detrás de otra, para no sumar
  // dos viajes de ida y vuelta a Supabase donde con uno alcanza.
  const wantsMetaCheck = thisRoundOutcome === "W" && !!thisRoundOpponentDeck;
  const [deckRes, meta, aliases] = await Promise.all([
    supabase.from("tournaments").select("my_deck, rounds").eq("customer_id", customerId),
    wantsMetaCheck ? getMetaArchetypes() : Promise.resolve(null),
    wantsMetaCheck ? getDeckAliases() : Promise.resolve([]),
  ]);
  const data = deckRes.data;

  let wins = 0, losses = 0, ties = 0;
  for (const t of (data || [])) {
    if (deckKey(t.my_deck) !== key) continue;
    for (const r of (t.rounds || [])) {
      const outcome = roundOutcome(r);
      if (outcome === "W") wins++;
      else if (outcome === "L") losses++;
      else if (outcome === "T") ties++;
    }
  }
  const total = wins + losses + ties;

  if (total >= 3 && await intentarDesbloquear(customerId, `mazo_muestra_${key}`)) {
    unlocked.push({ key: `mazo_muestra_${key}`, icon: "🧩", color: "#332A1C", title: "Mazo con muestra sólida",
      msg: "Ya tienes 3 partidas registradas con {mazo}. Suficiente para empezar a ver un patrón real.", deck: myDeck });
  }
  if (total >= 10 && await intentarDesbloquear(customerId, `mazo_consolidado_${key}`)) {
    unlocked.push({ key: `mazo_consolidado_${key}`, icon: "🧩", color: "#241D14", title: "Mazo consolidado",
      msg: "10 partidas con {mazo} — ya no es una racha, es tu mazo de verdad. ¿Qué tan bien te ha ido? Revísalo en tus estadísticas.", deck: myDeck });
  }
  const decisivas = wins + losses;
  const winrate = decisivas > 0 ? wins / decisivas : 0;
  if (decisivas >= 5 && winrate >= 0.6 && await intentarDesbloquear(customerId, `mazo_fuerte_${key}`)) {
    unlocked.push({ key: `mazo_fuerte_${key}`, icon: "💪", color: "#1C1710", title: "Mazo fuerte",
      msg: `{mazo} va con ${Math.round(winrate * 100)}% en ${total} partidas — tienes un mazo fuerte entre manos.`, deck: myDeck });
  }

  if (wantsMetaCheck) {
    const top = meta?.ok ? meta.archetypes[0] : null;
    // El meta ya viene con equivalencias aplicadas: se compara contra el rival "oficial".
    const oppCanon = canonicalDeck(thisRoundOpponentDeck, new Date().toISOString().slice(0, 10), aliases);
    if (top && deckKey(oppCanon) === deckKey({ p1: top.p1, p2: top.p2 })) {
      if (await intentarDesbloquear(customerId, "mazo_vencio_meta1")) {
        unlocked.push({ key: "mazo_vencio_meta1", icon: "🎯", color: "#141210", title: "¡Gran resultado!",
          msg: "Le ganaste al mazo #1 del meta actual ({mazo}). Buen resultado contra lo que más se está jugando.",
          deck: { p1: top.p1, p2: top.p2 } });
      }
    }
  }

  return unlocked;
}

/* =========================
   Presupuesto de gasto
   ---------------------------------------------------------------------
   Un presupuesto por usuario (tabla user_budgets, customer_id único):
   monto en pesos enteros y período "weekly" o "monthly". Monto vacío o 0
   quita el presupuesto. La alerta de "te pasaste" se calcula en la
   página con los torneos del usuario — acá solo se guarda el valor.
========================= */
async function getBudget(customerId) {
  try {
    const { data, error } = await supabase
      .from("user_budgets")
      .select("amount, period")
      .eq("customer_id", customerId)
      .maybeSingle();
    if (error) return null;
    return data || null;
  } catch (e) {
    return null;
  }
}

async function setBudget(customerId, q) {
  const amount = normalizeCost(q.amount);
  if (amount === undefined) return { ok: false, error: "Invalid amount" };

  if (amount === null || amount === 0) {
    const { error } = await supabase
      .from("user_budgets")
      .delete()
      .eq("customer_id", customerId);
    if (error) return { ok: false, error: "No se pudo quitar el presupuesto" };
    return { ok: true, budget: null };
  }

  if (q.period !== "weekly" && q.period !== "monthly") {
    return { ok: false, error: "Invalid period" };
  }

  const { data, error } = await supabase
    .from("user_budgets")
    .upsert(
      { customer_id: customerId, amount, period: q.period, updated_at: new Date().toISOString() },
      { onConflict: "customer_id" }
    )
    .select("amount, period")
    .single();

  if (error) return { ok: false, error: "No se pudo guardar el presupuesto" };
  return { ok: true, budget: data };
}

// Deja un registro liviano de uso para reportería (usuarios activos, nuevos,
// frecuencia, etc.). Nunca debe poder romper ni retrasar de forma relevante
// la respuesta real: cualquier falla (tabla no existe, Supabase lento, lo que
// sea) se traga acá mismo y no llega a afectar al usuario.
// Devuelve si quedó registrado o no. Para las otras 12 acciones esto es solo
// informativo (nunca les cambia su resultado, ver el handler más abajo); para
// "share_image" ES el resultado completo de la acción (no hay ninguna otra
// escritura detrás), así que ahí sí le importa a quien llamó.
async function logEvent(customerId, action) {
  try {
    const { error } = await supabase.from("app_events").insert([{ customer_id: customerId, action }]);
    return !error;
  } catch (e) {
    return false;
  }
}

// Acciones que escriben datos: exigen el token anti-CSRF y cuentan para el
// límite de acciones por minuto (ver más abajo). Leer/listar torneos no.
const WRITE_ACTIONS = new Set([
  "create_tournament", "update_tournament", "add_round", "delete_last_round",
  "move_round", "update_round", "delete_tournament", "set_final_result", "set_budget",
]);

// Sin esto, una sola cuenta (gratis y automática de crear) podía llamar
// create_tournament sin límite — suficiente para inflar/ensuciar el Meta de
// Arquetipos (que se calcula sobre TODOS los usuarios) o simplemente saturar
// la base. Se reusa app_events (ya se registra en cada acción) como bitácora
// para contar cuántas acciones de escritura hizo ese cliente en la última
// ventana, sin necesitar infraestructura nueva (Redis/KV).
const RATE_LIMIT_WINDOW_MS = 60_000;
const RATE_LIMIT_MAX_ACTIONS = 20;

async function isRateLimited(customerId) {
  try {
    const since = new Date(Date.now() - RATE_LIMIT_WINDOW_MS).toISOString();
    const { count, error } = await supabase
      .from("app_events")
      .select("id", { count: "exact", head: true })
      .eq("customer_id", customerId)
      .gte("created_at", since);
    if (error) return false; // si no se puede consultar, no bloqueamos por las dudas
    return (count ?? 0) >= RATE_LIMIT_MAX_ACTIONS;
  } catch (e) {
    return false;
  }
}

// Ejecuta la acción real pedida — separado del handler para poder correrlo
// en paralelo con logEvent() en vez de esperar a que termine primero.
async function runAction(customerId, action, q) {
  switch (action) {
    case "get_csrf_token":
      return { ok: true, csrf: computeCsrfToken(customerId, _csrfWindow(0)) };

    case "get_tournament":
      return await getTournamentOwned(customerId, q.id);

    case "list_tournaments": {
      // El presupuesto y las equivalencias de mazos viajan junto al listado
      // para no sumar otro viaje al servidor.
      const [tournaments, budget, aliases] = await Promise.all([
        listTournaments(customerId),
        getBudget(customerId),
        getDeckAliases(),
      ]);
      const deck_aliases = aliases.map(a => ({ from: a.from, to: a.to, until: a.until }));
      return { ok: true, tournaments, budget, deck_aliases };
    }

    case "set_budget":
      return await setBudget(customerId, q);

    case "get_meta_archetypes":
      return await getMetaArchetypes();

    case "get_meta_tier_list":
      return await getMetaTierList(q.range);

    case "create_tournament":
      return await createTournament(customerId, q);

    case "update_tournament":
      return await updateTournament(customerId, q.id, q);

    case "add_round":
      return await addRound(customerId, q.id);

    case "delete_last_round":
      return await deleteLastRound(customerId, q.id);

    case "move_round":
      return await moveRound(customerId, q.id, q.round_number, q.direction);

    case "update_round":
      return await updateRound(customerId, q.id, q);

    case "delete_tournament":
      return await deleteTournament(customerId, q.id);

    case "set_final_result":
      return await setFinalResult(customerId, q.id, q.result);

    case "share_image":
      // La imagen se genera y descarga 100% en el navegador (Canvas); esta
      // acción no tiene ninguna otra escritura — el handler reemplaza esta
      // respuesta con el resultado real de logEvent() (ver más abajo).
      return { ok: true };

    default:
      return { ok: false, error: "Unknown action" };
  }
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

  // Las acciones que escriben datos exigen el token anti-CSRF (ver más
  // arriba) y cuentan para el límite de acciones por minuto — ninguna de
  // las dos cosas aplica a leer/listar torneos, así que esa parte de la
  // app sigue exactamente igual de rápida que antes.
  if (WRITE_ACTIONS.has(action)) {
    if (!verifyCsrfToken(customerId, req.query.csrf)) {
      return res.status(403).json({ ok: false, error: "Sesión no verificada — recarga la página e inténtalo de nuevo." });
    }
    if (await isRateLimited(customerId)) {
      return res.status(429).json({ ok: false, error: "Demasiadas acciones seguidas — espera un minuto e inténtalo de nuevo." });
    }
  }

  // logEvent() y la acción real no dependen una de la otra — antes se
  // esperaba el registro de uso ANTES de arrancar cualquier otra cosa, en
  // las 13 acciones de la app. Ahora van en paralelo.
  const [logOk, result] = await Promise.all([
    logEvent(customerId, action),
    runAction(customerId, action, req.query),
  ]);
  // "share_image" es la única acción donde el registro de uso ES la acción
  // completa (no hay ninguna otra escritura) — ahí sí debe fallar de verdad
  // si no quedó guardado, para que la página lo note y reintente. En las
  // otras 12 el registro sigue siendo secundario: nunca les cambia el resultado.
  if (action === "share_image") return res.json({ ok: logOk });
  return res.json(result);
}
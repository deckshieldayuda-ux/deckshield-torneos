export default function handler(req, res) {
  res.status(200).json({
    ok: true,
    message: "DeckShield Torneos API funcionando",
    time: new Date().toISOString()
  });
}

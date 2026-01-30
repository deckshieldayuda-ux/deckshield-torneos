export default function handler(req, res) {
  res.status(200).json({
    ok: true,
    route: "proxy",
    query: req.query || {}
  });
}

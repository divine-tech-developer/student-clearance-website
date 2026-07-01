function ensureAuth(req, res, next) {
  if (!req.session.user) return res.redirect('/login');
  next();
}

function ensureAdmin(req, res, next) {
  if (!req.session.user) return res.redirect('/login');
  if (req.session.user.role !== 'admin') return res.status(403).send('Access denied');
  next();
}

function ensureStudent(req, res, next) {
  if (!req.session.user) return res.redirect('/login');
  if (req.session.user.role !== 'student') return res.status(403).send('Access denied');
  next();
}

module.exports = { ensureAuth, ensureAdmin, ensureStudent };
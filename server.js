require('dotenv').config();
const express = require('express');
const session = require('express-session');
const SQLiteStore = require('connect-sqlite3')(session);
const bcrypt = require('bcryptjs');
const methodOverride = require('method-override');
const db = require('./db');
const { ensureAuth, ensureAdmin, ensureStudent } = require('./middleware');

const app = express();
const PORT = process.env.PORT || 3000;

app.set('view engine', 'ejs');
app.use(express.urlencoded({ extended: true }));
app.use(express.static('public'));
app.use(methodOverride('_method'));

app.use(
  session({
    store: new SQLiteStore({ db: 'sessions.sqlite' }),
    secret: process.env.SESSION_SECRET || 'secret_key',
    resave: false,
    saveUninitialized: false,
    cookie: { maxAge: 1000 * 60 * 60 * 8 }
  })
);

app.use((req, res, next) => {
  res.locals.user = req.session.user || null;
  next();
});

app.get('/', (req, res) => {
  res.render('home');
});

app.get('/register', (req, res) => {
  res.render('register', { error: null });
});

app.post('/register', (req, res) => {
  const { fullname, email, password, confirm_password } = req.body;
  if (!fullname || !email || !password || !confirm_password) {
    return res.render('register', { error: 'All fields are required.' });
  }
  if (password !== confirm_password) {
    return res.render('register', { error: 'Passwords do not match.' });
  }

  const existing = db.prepare('SELECT * FROM users WHERE email = ?').get(email);
  if (existing) {
    return res.render('register', { error: 'Email already exists.' });
  }

  const hashed = bcrypt.hashSync(password, 10);
  const result = db.prepare(
    'INSERT INTO users (fullname, email, password, role) VALUES (?, ?, ?, ?)'
  ).run(fullname, email, hashed, 'student');

  const user = db.prepare('SELECT id, fullname, email, role FROM users WHERE id = ?').get(result.lastInsertRowid);
  req.session.user = user;
  res.redirect('/student/dashboard');
});

app.get('/login', (req, res) => {
  res.render('login', { error: null });
});

app.post('/login', (req, res) => {
  const { email, password } = req.body;
  const user = db.prepare('SELECT * FROM users WHERE email = ?').get(email);

  if (!user || !bcrypt.compareSync(password, user.password)) {
    return res.render('login', { error: 'Invalid email or password.' });
  }

  req.session.user = { id: user.id, fullname: user.fullname, email: user.email, role: user.role };

  if (user.role === 'admin') return res.redirect('/admin/dashboard');
  return res.redirect('/student/dashboard');
});

app.get('/logout', (req, res) => {
  req.session.destroy(() => res.redirect('/login'));
});

app.get('/student/dashboard', ensureStudent, (req, res) => {
  const studentId = req.session.user.id;
  const checkpoints = db.prepare('SELECT * FROM checkpoints ORDER BY id').all();
  const requests = db.prepare(`
    SELECT cr.*, c.name AS checkpoint_name
    FROM clearance_requests cr
    JOIN checkpoints c ON c.id = cr.checkpoint_id
    WHERE cr.student_id = ?
    ORDER BY cr.id DESC
  `).all(studentId);

  const summary = {
    total: checkpoints.length,
    approved: requests.filter(r => r.status === 'approved').length,
    pending: requests.filter(r => r.status === 'pending').length,
    rejected: requests.filter(r => r.status === 'rejected').length
  };

  res.render('student-dashboard', { checkpoints, requests, summary });
});

app.get('/student/request', ensureStudent, (req, res) => {
  const checkpoints = db.prepare('SELECT * FROM checkpoints ORDER BY id').all();
  const existing = db.prepare('SELECT checkpoint_id FROM clearance_requests WHERE student_id = ?').all(req.session.user.id);
  const existingIds = existing.map(e => e.checkpoint_id);
  res.render('student-request', { checkpoints, existingIds, error: null, success: null });
});

app.post('/student/request', ensureStudent, (req, res) => {
  const studentId = req.session.user.id;
  const { checkpoint_id } = req.body;

  if (!checkpoint_id) {
    const checkpoints = db.prepare('SELECT * FROM checkpoints ORDER BY id').all();
    const existing = db.prepare('SELECT checkpoint_id FROM clearance_requests WHERE student_id = ?').all(studentId);
    const existingIds = existing.map(e => e.checkpoint_id);
    return res.render('student-request', { checkpoints, existingIds, error: 'Please choose a checkpoint.', success: null });
  }

  try {
    db.prepare('INSERT INTO clearance_requests (student_id, checkpoint_id) VALUES (?, ?)').run(studentId, checkpoint_id);
    return res.redirect('/student/dashboard');
  } catch (err) {
    const checkpoints = db.prepare('SELECT * FROM checkpoints ORDER BY id').all();
    const existing = db.prepare('SELECT checkpoint_id FROM clearance_requests WHERE student_id = ?').all(studentId);
    const existingIds = existing.map(e => e.checkpoint_id);
    return res.render('student-request', {
      checkpoints,
      existingIds,
      error: 'You have already requested clearance for this checkpoint.',
      success: null
    });
  }
});

app.get('/student/slip', ensureStudent, (req, res) => {
  const studentId = req.session.user.id;
  const student = db.prepare('SELECT id, fullname, email FROM users WHERE id = ?').get(studentId);
  const requests = db.prepare(`
    SELECT c.name AS checkpoint_name, cr.status, cr.remarks, cr.updated_at
    FROM clearance_requests cr
    JOIN checkpoints c ON c.id = cr.checkpoint_id
    WHERE cr.student_id = ?
    ORDER BY c.id
  `).all(studentId);

  res.render('student-slip', { student, requests });
});

app.get('/admin/dashboard', ensureAdmin, (req, res) => {
  const totalStudents = db.prepare("SELECT COUNT(*) AS count FROM users WHERE role = 'student'").get().count;
  const totalCheckpoints = db.prepare('SELECT COUNT(*) AS count FROM checkpoints').get().count;
  const pendingRequests = db.prepare("SELECT COUNT(*) AS count FROM clearance_requests WHERE status = 'pending'").get().count;
  const approvedRequests = db.prepare("SELECT COUNT(*) AS count FROM clearance_requests WHERE status = 'approved'").get().count;

  const recentRequests = db.prepare(`
    SELECT cr.id, u.fullname, c.name AS checkpoint_name, cr.status, cr.updated_at
    FROM clearance_requests cr
    JOIN users u ON u.id = cr.student_id
    JOIN checkpoints c ON c.id = cr.checkpoint_id
    ORDER BY cr.id DESC
    LIMIT 8
  `).all();

  res.render('admin-dashboard', {
    totalStudents, totalCheckpoints, pendingRequests, approvedRequests, recentRequests
  });
});

app.get('/admin/checkpoints', ensureAdmin, (req, res) => {
  const checkpoints = db.prepare('SELECT * FROM checkpoints ORDER BY id').all();
  res.render('admin-checkpoints', { checkpoints, error: null });
});

app.post('/admin/checkpoints', ensureAdmin, (req, res) => {
  const { name } = req.body;
  if (!name) {
    const checkpoints = db.prepare('SELECT * FROM checkpoints ORDER BY id').all();
    return res.render('admin-checkpoints', { checkpoints, error: 'Checkpoint name is required.' });
  }
  try {
    db.prepare('INSERT INTO checkpoints (name) VALUES (?)').run(name.trim());
  } catch (err) {}
  res.redirect('/admin/checkpoints');
});

app.post('/admin/checkpoints/:id/delete', ensureAdmin, (req, res) => {
  db.prepare('DELETE FROM checkpoints WHERE id = ?').run(req.params.id);
  res.redirect('/admin/checkpoints');
});

app.get('/admin/requests', ensureAdmin, (req, res) => {
  const requests = db.prepare(`
    SELECT cr.id, u.fullname, u.email, c.name AS checkpoint_name, cr.status, cr.remarks, cr.updated_at
    FROM clearance_requests cr
    JOIN users u ON u.id = cr.student_id
    JOIN checkpoints c ON c.id = cr.checkpoint_id
    ORDER BY cr.id DESC
  `).all();
  res.render('admin-requests', { requests });
});

app.post('/admin/requests/:id/status', ensureAdmin, (req, res) => {
  const { status, remarks } = req.body;
  db.prepare('UPDATE clearance_requests SET status = ?, remarks = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?')
    .run(status, remarks || null, req.params.id);
  res.redirect('/admin/requests');
});

app.get('/admin/students', ensureAdmin, (req, res) => {
  const students = db.prepare("SELECT id, fullname, email, created_at FROM users WHERE role = 'student' ORDER BY id DESC").all();
  res.render('admin-students', { students });
});

app.listen(PORT, () => {
  console.log(`Server running on http://localhost:${PORT}`);
});
const Database = require('better-sqlite3');
const bcrypt = require('bcryptjs');

const db = new Database('output.sqlite');

db.exec(`
CREATE TABLE IF NOT EXISTS users (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  fullname TEXT NOT NULL,
  email TEXT NOT NULL UNIQUE,
  password TEXT NOT NULL,
  role TEXT NOT NULL CHECK(role IN ('admin', 'student')),
  created_at TEXT DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS checkpoints (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  name TEXT NOT NULL UNIQUE,
  created_at TEXT DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS clearance_requests (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  student_id INTEGER NOT NULL,
  checkpoint_id INTEGER NOT NULL,
  status TEXT NOT NULL DEFAULT 'pending' CHECK(status IN ('pending', 'approved', 'rejected')),
  remarks TEXT,
  updated_at TEXT DEFAULT CURRENT_TIMESTAMP,
  created_at TEXT DEFAULT CURRENT_TIMESTAMP,
  FOREIGN KEY(student_id) REFERENCES users(id),
  FOREIGN KEY(checkpoint_id) REFERENCES checkpoints(id),
  UNIQUE(student_id, checkpoint_id)
);
`);

const adminEmail = process.env.ADMIN_EMAIL || 'admin@school.edu';
const adminPassword = process.env.ADMIN_PASSWORD || 'Admin12345';

const existingAdmin = db.prepare('SELECT * FROM users WHERE role = ? LIMIT 1').get('admin');
if (!existingAdmin) {
  const hashed = bcrypt.hashSync(adminPassword, 10);
  db.prepare(
    'INSERT INTO users (fullname, email, password, role) VALUES (?, ?, ?, ?)'
  ).run('System Admin', adminEmail, hashed, 'admin');
}

const defaultCheckpoints = ['Library', 'Finance', 'Department', 'Hostel', 'ICT'];
const insertCheckpoint = db.prepare('INSERT OR IGNORE INTO checkpoints (name) VALUES (?)');
defaultCheckpoints.forEach((cp) => insertCheckpoint.run(cp));

module.exports = db;
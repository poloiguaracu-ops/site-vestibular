PRAGMA foreign_keys = ON;

CREATE TABLE IF NOT EXISTS candidates (
  id TEXT PRIMARY KEY,
  full_name TEXT NOT NULL,
  cpf_lookup_hash TEXT NOT NULL UNIQUE,
  cpf_encrypted TEXT NOT NULL,
  rg_encrypted TEXT NOT NULL,
  birth_date TEXT NOT NULL,
  sex TEXT NOT NULL,
  social_name TEXT,
  nationality TEXT NOT NULL,
  mother_name TEXT NOT NULL,
  father_name TEXT,
  cep TEXT NOT NULL,
  state TEXT NOT NULL,
  street TEXT NOT NULL,
  street_number TEXT NOT NULL,
  complement TEXT,
  neighborhood TEXT NOT NULL,
  city TEXT NOT NULL,
  phone TEXT NOT NULL,
  email TEXT NOT NULL,
  school_name TEXT NOT NULL,
  high_school_completion_year INTEGER NOT NULL,
  school_type TEXT NOT NULL,
  password_hash TEXT,
  created_at TEXT NOT NULL DEFAULT (datetime('now')),
  updated_at TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS applications (
  id TEXT PRIMARY KEY,
  protocol TEXT NOT NULL UNIQUE,
  candidate_id TEXT NOT NULL REFERENCES candidates(id),
  competition_type TEXT NOT NULL CHECK (competition_type IN ('Ampla concorrência','Cotas')),
  status TEXT NOT NULL DEFAULT 'Recebida',
  payment_status TEXT NOT NULL DEFAULT 'Pendente',
  payment_amount_cents INTEGER,
  payment_due_date TEXT,
  exam_date TEXT,
  exam_location_id TEXT,
  exam_room TEXT,
  result_status TEXT NOT NULL DEFAULT 'A divulgar',
  submitted_at TEXT NOT NULL DEFAULT (datetime('now')),
  updated_at TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS application_choices (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  application_id TEXT NOT NULL REFERENCES applications(id) ON DELETE CASCADE,
  preference_order INTEGER NOT NULL CHECK (preference_order BETWEEN 1 AND 3),
  course_name TEXT NOT NULL,
  study_location TEXT NOT NULL,
  study_mode TEXT NOT NULL CHECK (study_mode IN ('Presencial','Semipresencial','Online (EAD)')),
  UNIQUE(application_id, preference_order)
);

CREATE TABLE IF NOT EXISTS exam_locations (
  id TEXT PRIMARY KEY,
  title TEXT NOT NULL,
  address TEXT NOT NULL,
  city TEXT NOT NULL,
  state TEXT NOT NULL,
  instructions TEXT,
  active INTEGER NOT NULL DEFAULT 1,
  created_at TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS payments (
  id TEXT PRIMARY KEY,
  application_id TEXT NOT NULL REFERENCES applications(id) ON DELETE CASCADE,
  amount_cents INTEGER NOT NULL,
  status TEXT NOT NULL DEFAULT 'Pendente',
  payment_method TEXT,
  external_reference TEXT,
  paid_at TEXT,
  confirmed_by TEXT,
  notes TEXT,
  created_at TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS candidate_sessions (
  id TEXT PRIMARY KEY,
  candidate_id TEXT NOT NULL REFERENCES candidates(id) ON DELETE CASCADE,
  token_hash TEXT NOT NULL UNIQUE,
  expires_at TEXT NOT NULL,
  created_at TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS admin_users (
  id TEXT PRIMARY KEY,
  username TEXT NOT NULL UNIQUE,
  password_hash TEXT NOT NULL,
  display_name TEXT NOT NULL,
  role TEXT NOT NULL DEFAULT 'gestor',
  active INTEGER NOT NULL DEFAULT 1,
  created_at TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS announcements (
  id TEXT PRIMARY KEY,
  title TEXT NOT NULL,
  body TEXT NOT NULL,
  audience TEXT NOT NULL DEFAULT 'Todos',
  published INTEGER NOT NULL DEFAULT 0,
  published_at TEXT,
  created_at TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE INDEX IF NOT EXISTS idx_applications_candidate ON applications(candidate_id);
CREATE INDEX IF NOT EXISTS idx_applications_status ON applications(status);
CREATE INDEX IF NOT EXISTS idx_choices_application ON application_choices(application_id);
CREATE INDEX IF NOT EXISTS idx_payments_application ON payments(application_id);
CREATE INDEX IF NOT EXISTS idx_sessions_expiry ON candidate_sessions(expires_at);

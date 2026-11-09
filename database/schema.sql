PRAGMA foreign_keys = ON;

-- Banco do Vestibular de Verão UniFil 2027 — Polo Iguaraçu
-- Execute este arquivo em um banco Cloudflare D1 novo.
-- Não armazene senhas em texto puro. Campos de senha recebem somente hashes.

CREATE TABLE IF NOT EXISTS candidates (
  id TEXT PRIMARY KEY,
  full_name TEXT NOT NULL,
  social_name TEXT,
  cpf TEXT NOT NULL UNIQUE,
  rg TEXT NOT NULL,
  birth_date TEXT NOT NULL,
  sex TEXT NOT NULL,
  nationality TEXT NOT NULL,
  mother_name TEXT NOT NULL,
  father_name TEXT,
  cep TEXT NOT NULL,
  state_uf TEXT NOT NULL,
  street TEXT NOT NULL,
  street_number TEXT NOT NULL,
  address_complement TEXT,
  neighborhood TEXT NOT NULL,
  city TEXT NOT NULL,
  phone TEXT NOT NULL,
  email TEXT NOT NULL,
  high_school_name TEXT NOT NULL,
  high_school_completion_year INTEGER NOT NULL,
  high_school_type TEXT NOT NULL CHECK (high_school_type IN ('Pública', 'Particular')),
  password_hash TEXT,
  password_salt TEXT,
  account_status TEXT NOT NULL DEFAULT 'pending' CHECK (account_status IN ('pending', 'active', 'blocked')),
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS applications (
  id TEXT PRIMARY KEY,
  protocol TEXT NOT NULL UNIQUE,
  candidate_id TEXT NOT NULL REFERENCES candidates(id) ON DELETE RESTRICT,
  process_name TEXT NOT NULL DEFAULT 'Vestibular de Verão UniFil 2027',
  competition_type TEXT NOT NULL,
  application_status TEXT NOT NULL DEFAULT 'received'
    CHECK (application_status IN ('received', 'under_review', 'confirmed', 'rejected', 'cancelled')),
  payment_status TEXT NOT NULL DEFAULT 'pending'
    CHECK (payment_status IN ('pending', 'paid', 'waived', 'refunded', 'cancelled')),
  fee_amount_cents INTEGER NOT NULL DEFAULT 2990 CHECK (fee_amount_cents >= 0),
  payment_due_date TEXT,
  payment_confirmed_at TEXT,
  exam_location TEXT,
  exam_room TEXT,
  exam_date TEXT,
  exam_time TEXT,
  result_status TEXT NOT NULL DEFAULT 'not_published'
    CHECK (result_status IN ('not_published', 'approved', 'classified', 'waitlisted', 'not_approved')),
  result_published_at TEXT,
  privacy_notice_version TEXT NOT NULL,
  privacy_consent_at TEXT NOT NULL,
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS course_choices (
  id TEXT PRIMARY KEY,
  application_id TEXT NOT NULL REFERENCES applications(id) ON DELETE CASCADE,
  preference_order INTEGER NOT NULL CHECK (preference_order BETWEEN 1 AND 3),
  course_name TEXT NOT NULL,
  study_location TEXT NOT NULL,
  study_modality TEXT NOT NULL CHECK (study_modality IN ('Presencial', 'Semipresencial', 'Online (EAD)')),
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  UNIQUE (application_id, preference_order)
);

CREATE TABLE IF NOT EXISTS payments (
  id TEXT PRIMARY KEY,
  application_id TEXT NOT NULL REFERENCES applications(id) ON DELETE RESTRICT,
  provider TEXT,
  provider_reference TEXT,
  amount_cents INTEGER NOT NULL CHECK (amount_cents >= 0),
  payment_method TEXT,
  payment_status TEXT NOT NULL DEFAULT 'pending'
    CHECK (payment_status IN ('pending', 'paid', 'failed', 'refunded', 'cancelled')),
  due_date TEXT,
  paid_at TEXT,
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS admin_users (
  id TEXT PRIMARY KEY,
  full_name TEXT NOT NULL,
  email TEXT NOT NULL UNIQUE,
  password_hash TEXT NOT NULL,
  password_salt TEXT NOT NULL,
  role TEXT NOT NULL CHECK (role IN ('gestor', 'gestor_auxiliar')),
  active INTEGER NOT NULL DEFAULT 1 CHECK (active IN (0, 1)),
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS sessions (
  id TEXT PRIMARY KEY,
  subject_id TEXT NOT NULL,
  subject_type TEXT NOT NULL CHECK (subject_type IN ('candidate', 'admin')),
  token_hash TEXT NOT NULL UNIQUE,
  expires_at TEXT NOT NULL,
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS application_events (
  id TEXT PRIMARY KEY,
  application_id TEXT NOT NULL REFERENCES applications(id) ON DELETE CASCADE,
  actor_type TEXT NOT NULL CHECK (actor_type IN ('candidate', 'admin', 'system')),
  actor_id TEXT,
  event_type TEXT NOT NULL,
  description TEXT NOT NULL,
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS system_settings (
  setting_key TEXT PRIMARY KEY,
  setting_value TEXT NOT NULL,
  updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_candidates_name ON candidates(full_name);
CREATE INDEX IF NOT EXISTS idx_candidates_email ON candidates(email);
CREATE INDEX IF NOT EXISTS idx_applications_candidate ON applications(candidate_id);
CREATE INDEX IF NOT EXISTS idx_applications_status ON applications(application_status);
CREATE INDEX IF NOT EXISTS idx_applications_created ON applications(created_at);
CREATE INDEX IF NOT EXISTS idx_course_choices_course ON course_choices(course_name);
CREATE INDEX IF NOT EXISTS idx_payments_application ON payments(application_id);
CREATE INDEX IF NOT EXISTS idx_sessions_expiry ON sessions(expires_at);
CREATE INDEX IF NOT EXISTS idx_events_application ON application_events(application_id, created_at);

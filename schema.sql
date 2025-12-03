CREATE TABLE IF NOT EXISTS users (
  id            BIGSERIAL PRIMARY KEY,
  name          VARCHAR(120) NOT NULL,
  rut           VARCHAR(20)  NOT NULL UNIQUE,  -- almacenado normalizado (sin puntos, con guión)
  email         VARCHAR(160) NOT NULL UNIQUE,
  password_hash TEXT         NOT NULL,
  role          VARCHAR(40)  NOT NULL DEFAULT 'user',
  created_at    TIMESTAMPTZ  NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_users_rut ON users (rut);
CREATE INDEX IF NOT EXISTS idx_users_email ON users (email);
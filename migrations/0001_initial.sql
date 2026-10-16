
CREATE TABLE IF NOT EXISTS oauth_transactions (
    id_hash TEXT PRIMARY KEY,
    provider TEXT NOT NULL CHECK (provider IN ('google', 'github')),
    state_hash TEXT NOT NULL,
    nonce TEXT,
    code_verifier TEXT,
    expires_at INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS sessions (
    id_hash TEXT PRIMARY KEY,
    issuer TEXT NOT NULL,
    subject TEXT NOT NULL,
    email TEXT,
    display_name TEXT,
    expires_at INTEGER NOT NULL,
    created_at INTEGER NOT NULL DEFAULT (unixepoch())
);

CREATE INDEX IF NOT EXISTS oauth_transactions_expiry
ON oauth_transactions (expires_at);

CREATE INDEX IF NOT EXISTS sessions_expiry
ON sessions (expires_at);


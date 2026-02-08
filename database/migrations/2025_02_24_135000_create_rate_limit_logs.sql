CREATE TABLE rate_limit_logs (
    id              BIGSERIAL PRIMARY KEY,
    method          VARCHAR(10) NOT NULL,
    path            VARCHAR(2048) NOT NULL,
    key_type        VARCHAR(20) NOT NULL,
    key_hash        VARCHAR(100) NOT NULL,
    scope           VARCHAR(50) NOT NULL DEFAULT 'default',
    retry_after     INTEGER NOT NULL DEFAULT 0,
    client_ip       VARCHAR(45) NOT NULL,
    denied_at       TIMESTAMPTZ NOT NULL DEFAULT (NOW() AT TIME ZONE 'UTC'),
    created_at      TIMESTAMPTZ DEFAULT (NOW() AT TIME ZONE 'UTC')
);

-- Index for querying recent denials by scope / key
CREATE INDEX idx_rate_limit_logs_scope_denied ON rate_limit_logs (scope, denied_at DESC);
CREATE INDEX idx_rate_limit_logs_client_ip    ON rate_limit_logs (client_ip, denied_at DESC);
CREATE INDEX idx_rate_limit_logs_key_hash     ON rate_limit_logs (key_hash, denied_at DESC);

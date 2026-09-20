-- Sentrix database schema
-- users: one row per unique user seen in the activity data
CREATE TABLE users (
    user_id VARCHAR(20) PRIMARY KEY,
    role VARCHAR(20) NOT NULL
);

-- security_events: the fact table — one row per raw event, immutable
CREATE TABLE security_events (
    event_id UUID PRIMARY KEY,
    user_id VARCHAR(20) NOT NULL REFERENCES users(user_id),
    timestamp TIMESTAMP NOT NULL,
    source_ip VARCHAR(45) NOT NULL,
    country VARCHAR(5) NOT NULL,
    action VARCHAR(50) NOT NULL,
    status VARCHAR(20) NOT NULL,
    is_privileged_action BOOLEAN NOT NULL
);

-- risk_scores: computed judgment about an event, kept separate so
-- re-scoring later never risks corrupting the original event record
CREATE TABLE risk_scores (
    event_id UUID PRIMARY KEY REFERENCES security_events(event_id),
    anomaly_score FLOAT NOT NULL,
    anomaly_score_normalized FLOAT NOT NULL,
    risk_score FLOAT NOT NULL,
    severity VARCHAR(10) NOT NULL,
    rules_triggered INT NOT NULL
);

-- anomalies: ground-truth / confirmed-incident records for flagged events
CREATE TABLE anomalies (
    event_id UUID PRIMARY KEY REFERENCES security_events(event_id),
    is_attack BOOLEAN NOT NULL,
    attack_type VARCHAR(30)
);

-- alerts: generated for HIGH/CRITICAL severity events only
CREATE TABLE alerts (
    alert_id SERIAL PRIMARY KEY,
    event_id UUID NOT NULL REFERENCES security_events(event_id),
    severity VARCHAR(10) NOT NULL,
    created_at TIMESTAMP NOT NULL DEFAULT NOW(),
    status VARCHAR(20) NOT NULL DEFAULT 'OPEN'
);

-- Indexes: columns we'll filter/search on frequently
CREATE INDEX idx_events_user_id ON security_events(user_id);
CREATE INDEX idx_events_timestamp ON security_events(timestamp);
CREATE INDEX idx_risk_scores_severity ON risk_scores(severity);
CREATE INDEX idx_alerts_status ON alerts(status);
CREATE TABLE app_users (
    app_user_id SERIAL PRIMARY KEY,
    username VARCHAR(50) UNIQUE NOT NULL,
    password_hash VARCHAR(255) NOT NULL,
    role VARCHAR(20) NOT NULL CHECK (role IN ('admin', 'analyst', 'viewer')),
    created_at TIMESTAMP NOT NULL DEFAULT NOW()
);
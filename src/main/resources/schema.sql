CREATE UNIQUE INDEX idx_auth_session_unique_device
    ON auth_sessions (user_id, created_ip, user_agent)
    WHERE (revoked_at IS NULL);
-- Index to support "same client_fingerprint across multiple accounts" detection,
-- i.e. GROUP BY client_fingerprint HAVING COUNT(DISTINCT user_id) > 1.
--
-- Partial index (client_fingerprint IS NOT NULL) keeps it small since non-Claude-Code
-- traffic and historical rows have NULL. Created CONCURRENTLY so writes to usage_logs
-- keep flowing during the build (requires _notx, non-tx runner).
CREATE INDEX CONCURRENTLY IF NOT EXISTS usagelog_client_fingerprint_user_id
    ON usage_logs (client_fingerprint, user_id)
    WHERE client_fingerprint IS NOT NULL;

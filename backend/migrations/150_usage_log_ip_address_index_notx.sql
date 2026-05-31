-- Composite index to support "same IP across multiple accounts" detection,
-- i.e. GROUP BY ip_address HAVING COUNT(DISTINCT user_id) >= N.
--
-- A single-column index idx_usage_logs_ip_address already exists (migration 031),
-- but it does not cover COUNT(DISTINCT user_id): that still has to visit the heap
-- per row. This (ip_address, user_id) composite lets the distinct-user aggregation
-- run index-only. It complements — does not replace — the single-column index,
-- which still serves point lookups / range scans on ip_address alone.
--
-- Partial index (ip_address IS NOT NULL) keeps it small. Created CONCURRENTLY so
-- writes to usage_logs keep flowing during the build (requires _notx, non-tx runner).
CREATE INDEX CONCURRENTLY IF NOT EXISTS usagelog_ip_address_user_id
    ON usage_logs (ip_address, user_id)
    WHERE ip_address IS NOT NULL;

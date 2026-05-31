-- Index to support "same device_id across multiple accounts" detection queries,
-- i.e. GROUP BY device_id HAVING COUNT(DISTINCT user_id) > 1.
--
-- Partial index (device_id IS NOT NULL) keeps it small since most historical rows
-- and all non-Claude-Code traffic have a NULL device_id. Created CONCURRENTLY so
-- writes to usage_logs keep flowing during the build (requires _notx, non-tx runner).
CREATE INDEX CONCURRENTLY IF NOT EXISTS usagelog_device_id_user_id
    ON usage_logs (device_id, user_id)
    WHERE device_id IS NOT NULL;

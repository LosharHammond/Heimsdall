-- Fast path: decisions made in-process from the signed policy bundle and synced in the background.
ALTER TABLE action_requests DROP CONSTRAINT IF EXISTS action_requests_source_check;
ALTER TABLE action_requests ADD CONSTRAINT action_requests_source_check CHECK (source IN ('online', 'offline_cache', 'local_fast'));

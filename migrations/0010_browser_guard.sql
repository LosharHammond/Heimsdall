-- Browser guard: the Heimdall extension for Chrome and Edge checks what is pasted or sent into AI chat sites.
ALTER TABLE agents DROP CONSTRAINT IF EXISTS agents_integration_type_check;
ALTER TABLE agents ADD CONSTRAINT agents_integration_type_check CHECK (integration_type IN ('typescript_sdk', 'event_reporting', 'auto_discovered', 'browser_extension'));

-- Automatic discovery of AI tools and agents on added computers (docs/DISCOVERY.md).
ALTER TABLE agents DROP CONSTRAINT IF EXISTS agents_integration_type_check;
ALTER TABLE agents ADD CONSTRAINT agents_integration_type_check CHECK (integration_type IN ('typescript_sdk', 'event_reporting', 'auto_discovered'));

CREATE TABLE discovered_tools (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  org_id uuid NOT NULL REFERENCES organizations (id) ON DELETE CASCADE,
  device_id uuid NOT NULL REFERENCES devices (id) ON DELETE CASCADE,
  key text NOT NULL CHECK (length(key) BETWEEN 1 AND 80),
  kind text NOT NULL CHECK (kind IN ('mcp_client', 'coding_agent', 'ai_app', 'local_model', 'agent_script', 'automation')),
  product text NOT NULL CHECK (length(product) BETWEEN 1 AND 80),
  detail text NOT NULL DEFAULT '' CHECK (length(detail) <= 200),
  protectable boolean NOT NULL,
  protection text NOT NULL CHECK (protection IN ('protected', 'restart_needed', 'unprotected', 'not_possible', 'off')),
  running boolean NOT NULL DEFAULT false,
  agent_id uuid REFERENCES agents (id) ON DELETE SET NULL,
  first_seen_at timestamptz NOT NULL DEFAULT now(),
  last_seen_at timestamptz NOT NULL DEFAULT now(),
  UNIQUE (device_id, key)
);
CREATE INDEX discovered_tools_org ON discovered_tools (org_id, last_seen_at DESC);

-- Protect found tools automatically (default). Off: tools are only listed.
ALTER TABLE organizations ADD COLUMN auto_protect boolean NOT NULL DEFAULT true;

-- Devices, companion health, notification delivery, executor attestations, offline sync provenance.

ALTER TABLE authorization_decisions ADD COLUMN classification_level text;
ALTER TABLE authorization_decisions ADD COLUMN classification_source text;
ALTER TABLE action_requests ADD COLUMN source text NOT NULL DEFAULT 'online' CHECK (source IN ('online', 'offline_cache'));

-- An enrolled device runs the native companion. Enrollment is explicit and revocable.
CREATE TABLE devices (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  org_id uuid NOT NULL REFERENCES organizations (id) ON DELETE CASCADE,
  name text NOT NULL CHECK (length(name) BETWEEN 1 AND 120),
  platform text NOT NULL DEFAULT 'windows' CHECK (platform IN ('windows', 'linux', 'macos', 'other')),
  status text NOT NULL DEFAULT 'pending' CHECK (status IN ('pending', 'active', 'revoked', 'removed')),
  enrolled_by uuid REFERENCES users (id),
  created_at timestamptz NOT NULL DEFAULT now(),
  enrolled_at timestamptz,
  last_heartbeat_at timestamptz,
  companion_version text,
  health jsonb NOT NULL DEFAULT '{}'::jsonb,
  notification_state text,
  notification_checked_at timestamptz,
  consent jsonb NOT NULL DEFAULT '{}'::jsonb,
  policy_cache jsonb NOT NULL DEFAULT '{}'::jsonb,
  revoked_at timestamptz,
  revoked_by uuid REFERENCES users (id),
  UNIQUE (id, org_id),
  UNIQUE (org_id, name)
);
CREATE INDEX devices_org_idx ON devices (org_id, created_at DESC);

CREATE TABLE device_credentials (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  org_id uuid NOT NULL,
  device_id uuid NOT NULL,
  prefix text NOT NULL UNIQUE,
  secret_hash text NOT NULL,
  kind text NOT NULL DEFAULT 'enrollment' CHECK (kind IN ('enrollment', 'device')),
  created_at timestamptz NOT NULL DEFAULT now(),
  expires_at timestamptz,
  last_used_at timestamptz,
  revoked_at timestamptz,
  FOREIGN KEY (device_id, org_id) REFERENCES devices (id, org_id) ON DELETE CASCADE
);
CREATE INDEX device_credentials_device_idx ON device_credentials (device_id);

-- Work a device should do (safe protection test, test notification). Never arbitrary commands.
CREATE TABLE device_commands (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  org_id uuid NOT NULL,
  device_id uuid NOT NULL,
  kind text NOT NULL CHECK (kind IN ('selftest', 'test_notification')),
  status text NOT NULL DEFAULT 'pending' CHECK (status IN ('pending', 'running', 'done', 'failed', 'expired')),
  requested_by uuid REFERENCES users (id),
  created_at timestamptz NOT NULL DEFAULT now(),
  completed_at timestamptz,
  result jsonb NOT NULL DEFAULT '{}'::jsonb,
  FOREIGN KEY (device_id, org_id) REFERENCES devices (id, org_id) ON DELETE CASCADE
);
CREATE INDEX device_commands_device_idx ON device_commands (device_id, status, created_at);

-- One delivery record per alert per device: this is what de-duplicates notifications across reconnects.
CREATE TABLE notification_deliveries (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  org_id uuid NOT NULL,
  device_id uuid NOT NULL,
  alert_id uuid NOT NULL REFERENCES alerts (id) ON DELETE CASCADE,
  state text NOT NULL CHECK (state IN ('shown', 'coalesced', 'suppressed_disabled', 'suppressed_policy', 'failed')),
  detail text,
  delivered_at timestamptz NOT NULL DEFAULT now(),
  UNIQUE (alert_id, device_id),
  FOREIGN KEY (device_id, org_id) REFERENCES devices (id, org_id) ON DELETE CASCADE
);

-- What an integrated executor attests about itself (protected roots, egress, policy cache). Evidence, not proof.
CREATE TABLE executor_status (
  agent_id uuid PRIMARY KEY,
  org_id uuid NOT NULL,
  reported_at timestamptz NOT NULL DEFAULT now(),
  executor_version text,
  roots jsonb NOT NULL DEFAULT '[]'::jsonb,
  egress_enabled boolean NOT NULL DEFAULT false,
  mode text NOT NULL DEFAULT 'online' CHECK (mode IN ('online', 'offline_cache', 'degraded')),
  cache_expires_at timestamptz,
  queued_events integer NOT NULL DEFAULT 0,
  FOREIGN KEY (agent_id, org_id) REFERENCES agents (id, org_id) ON DELETE CASCADE
);

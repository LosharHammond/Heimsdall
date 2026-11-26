-- Kenuxa Heimdall: initial schema. All timestamps are timestamptz (stored as UTC).

CREATE TABLE users (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  email text NOT NULL CHECK (email = lower(email) AND length(email) BETWEEN 3 AND 254),
  name text NOT NULL CHECK (length(name) BETWEEN 1 AND 120),
  password_hash text NOT NULL,
  created_at timestamptz NOT NULL DEFAULT now()
);
CREATE UNIQUE INDEX users_email_key ON users (email);

CREATE TABLE sessions (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id uuid NOT NULL REFERENCES users (id) ON DELETE CASCADE,
  token_hash text NOT NULL UNIQUE,
  created_at timestamptz NOT NULL DEFAULT now(),
  expires_at timestamptz NOT NULL,
  revoked_at timestamptz
);
CREATE INDEX sessions_user_idx ON sessions (user_id);
CREATE INDEX sessions_expires_idx ON sessions (expires_at);

CREATE TABLE organizations (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  name text NOT NULL CHECK (length(name) BETWEEN 2 AND 120),
  timezone text NOT NULL DEFAULT 'Africa/Accra',
  retention_days integer NOT NULL DEFAULT 90 CHECK (retention_days BETWEEN 7 AND 730),
  audit_retention_days integer NOT NULL DEFAULT 365 CHECK (audit_retention_days BETWEEN 30 AND 3650),
  created_by uuid REFERENCES users (id),
  created_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE memberships (
  org_id uuid NOT NULL REFERENCES organizations (id) ON DELETE CASCADE,
  user_id uuid NOT NULL REFERENCES users (id) ON DELETE CASCADE,
  role text NOT NULL CHECK (role IN ('owner', 'admin', 'viewer')),
  created_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (org_id, user_id)
);
CREATE INDEX memberships_user_idx ON memberships (user_id);

CREATE TABLE policies (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  org_id uuid NOT NULL REFERENCES organizations (id) ON DELETE CASCADE,
  name text NOT NULL CHECK (length(name) BETWEEN 1 AND 120),
  description text NOT NULL DEFAULT '',
  current_version integer NOT NULL DEFAULT 1,
  created_by uuid REFERENCES users (id),
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now(),
  UNIQUE (org_id, name),
  UNIQUE (id, org_id)
);

CREATE TABLE policy_versions (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  policy_id uuid NOT NULL,
  org_id uuid NOT NULL,
  version integer NOT NULL,
  document jsonb NOT NULL,
  document_hash text NOT NULL,
  created_by uuid REFERENCES users (id),
  created_at timestamptz NOT NULL DEFAULT now(),
  UNIQUE (policy_id, version),
  FOREIGN KEY (policy_id, org_id) REFERENCES policies (id, org_id) ON DELETE CASCADE
);

CREATE TABLE agents (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  org_id uuid NOT NULL REFERENCES organizations (id) ON DELETE CASCADE,
  name text NOT NULL CHECK (length(name) BETWEEN 1 AND 120),
  description text NOT NULL DEFAULT '' CHECK (length(description) <= 1000),
  environment text NOT NULL CHECK (environment IN ('development', 'staging', 'production')),
  integration_type text NOT NULL CHECK (integration_type IN ('typescript_sdk', 'event_reporting')),
  status text NOT NULL DEFAULT 'active' CHECK (status IN ('active', 'revoked')),
  policy_id uuid,
  enforcement_mode text NOT NULL DEFAULT 'enforce' CHECK (enforcement_mode IN ('monitor', 'enforce')),
  created_by uuid REFERENCES users (id),
  created_at timestamptz NOT NULL DEFAULT now(),
  last_seen_at timestamptz,
  last_authorized_at timestamptz,
  last_enforced_at timestamptz,
  revoked_at timestamptz,
  revoked_by uuid REFERENCES users (id),
  UNIQUE (org_id, name, environment),
  UNIQUE (id, org_id),
  FOREIGN KEY (policy_id, org_id) REFERENCES policies (id, org_id)
);
CREATE INDEX agents_org_idx ON agents (org_id, created_at DESC);

CREATE TABLE integration_credentials (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  org_id uuid NOT NULL,
  agent_id uuid NOT NULL,
  name text NOT NULL CHECK (length(name) BETWEEN 1 AND 120),
  prefix text NOT NULL UNIQUE,
  secret_hash text NOT NULL,
  scopes text[] NOT NULL CHECK (cardinality(scopes) > 0 AND scopes <@ ARRAY['actions', 'events']::text[]),
  created_by uuid REFERENCES users (id),
  created_at timestamptz NOT NULL DEFAULT now(),
  last_used_at timestamptz,
  revoked_at timestamptz,
  revoked_by uuid REFERENCES users (id),
  replaced_by uuid,
  UNIQUE (id, org_id),
  FOREIGN KEY (agent_id, org_id) REFERENCES agents (id, org_id) ON DELETE CASCADE
);
CREATE INDEX credentials_agent_idx ON integration_credentials (agent_id);

CREATE TABLE action_requests (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  org_id uuid NOT NULL,
  agent_id uuid NOT NULL,
  credential_id uuid NOT NULL REFERENCES integration_credentials (id),
  request_id text NOT NULL,
  tool text NOT NULL,
  operation text NOT NULL CHECK (operation IN ('read', 'create', 'update', 'delete', 'external_transfer', 'command_execution')),
  resource text NOT NULL,
  destination text,
  data_classification text CHECK (data_classification IN ('public', 'internal', 'confidential', 'restricted')),
  args_summary jsonb NOT NULL DEFAULT '{}'::jsonb,
  action_digest text NOT NULL,
  is_demo boolean NOT NULL DEFAULT false,
  adapter_name text,
  adapter_version text,
  requested_at timestamptz,
  created_at timestamptz NOT NULL DEFAULT now(),
  UNIQUE (agent_id, request_id),
  UNIQUE (id, org_id),
  FOREIGN KEY (agent_id, org_id) REFERENCES agents (id, org_id) ON DELETE CASCADE
);
CREATE INDEX action_requests_org_idx ON action_requests (org_id, created_at DESC);
CREATE INDEX action_requests_agent_idx ON action_requests (agent_id, created_at DESC);

-- Authorization decisions are separate from execution outcomes: "allowed" never implies "executed".
CREATE TABLE authorization_decisions (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  action_request_id uuid NOT NULL UNIQUE,
  org_id uuid NOT NULL,
  agent_id uuid NOT NULL,
  decision text NOT NULL CHECK (decision IN ('allow', 'deny', 'require_approval')),
  policy_decision text NOT NULL CHECK (policy_decision IN ('allow', 'deny', 'require_approval')),
  enforcement_mode text NOT NULL CHECK (enforcement_mode IN ('monitor', 'enforce')),
  reason_code text NOT NULL,
  explanation text NOT NULL,
  policy_id uuid,
  policy_version integer,
  matched_rule_id text,
  expires_at timestamptz NOT NULL,
  created_at timestamptz NOT NULL DEFAULT now(),
  FOREIGN KEY (action_request_id, org_id) REFERENCES action_requests (id, org_id) ON DELETE CASCADE
);
CREATE INDEX decisions_org_idx ON authorization_decisions (org_id, created_at DESC);
CREATE INDEX decisions_agent_idx ON authorization_decisions (agent_id, created_at DESC);

CREATE TABLE approvals (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  org_id uuid NOT NULL,
  action_request_id uuid NOT NULL UNIQUE,
  agent_id uuid NOT NULL,
  action_digest text NOT NULL,
  policy_id uuid NOT NULL,
  policy_version integer NOT NULL,
  required_role text NOT NULL CHECK (required_role IN ('admin', 'owner')),
  status text NOT NULL DEFAULT 'pending' CHECK (status IN ('pending', 'approved', 'rejected', 'expired')),
  requested_at timestamptz NOT NULL DEFAULT now(),
  expires_at timestamptz NOT NULL,
  grant_expires_at timestamptz,
  decided_by uuid REFERENCES users (id),
  decided_at timestamptz,
  decision_note text CHECK (length(decision_note) <= 500),
  consumed_at timestamptz,
  FOREIGN KEY (action_request_id, org_id) REFERENCES action_requests (id, org_id) ON DELETE CASCADE
);
CREATE INDEX approvals_org_idx ON approvals (org_id, status, requested_at DESC);

CREATE TABLE execution_outcomes (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  action_request_id uuid NOT NULL UNIQUE,
  org_id uuid NOT NULL,
  agent_id uuid NOT NULL,
  status text NOT NULL CHECK (status IN ('claimed', 'succeeded', 'failed', 'refused')),
  enforcement_confirmed boolean NOT NULL DEFAULT false,
  claim_policy_version integer,
  claimed_at timestamptz,
  reported_at timestamptz,
  error_code text,
  detail jsonb NOT NULL DEFAULT '{}'::jsonb,
  created_at timestamptz NOT NULL DEFAULT now(),
  FOREIGN KEY (action_request_id, org_id) REFERENCES action_requests (id, org_id) ON DELETE CASCADE
);
CREATE INDEX outcomes_org_idx ON execution_outcomes (org_id, created_at DESC);

-- Observations: events reported by an integration. Nothing here says anything was blocked.
CREATE TABLE observed_events (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  org_id uuid NOT NULL,
  agent_id uuid NOT NULL,
  credential_id uuid NOT NULL REFERENCES integration_credentials (id),
  event_id text,
  event_type text NOT NULL CHECK (length(event_type) BETWEEN 1 AND 64),
  tool text,
  operation text,
  resource text,
  summary jsonb NOT NULL DEFAULT '{}'::jsonb,
  is_demo boolean NOT NULL DEFAULT false,
  occurred_at timestamptz,
  created_at timestamptz NOT NULL DEFAULT now(),
  FOREIGN KEY (agent_id, org_id) REFERENCES agents (id, org_id) ON DELETE CASCADE
);
CREATE INDEX observed_events_org_idx ON observed_events (org_id, created_at DESC);
CREATE UNIQUE INDEX observed_events_dedupe ON observed_events (agent_id, event_id) WHERE event_id IS NOT NULL;

CREATE TABLE alerts (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  org_id uuid NOT NULL REFERENCES organizations (id) ON DELETE CASCADE,
  agent_id uuid,
  action_request_id uuid,
  kind text NOT NULL,
  severity text NOT NULL CHECK (severity IN ('low', 'medium', 'high')),
  title text NOT NULL,
  detail text NOT NULL DEFAULT '',
  status text NOT NULL DEFAULT 'open' CHECK (status IN ('open', 'acknowledged', 'resolved')),
  dedupe_key text,
  occurrences integer NOT NULL DEFAULT 1,
  is_demo boolean NOT NULL DEFAULT false,
  created_at timestamptz NOT NULL DEFAULT now(),
  last_seen_at timestamptz NOT NULL DEFAULT now(),
  handled_by uuid REFERENCES users (id),
  handled_at timestamptz
);
CREATE INDEX alerts_org_idx ON alerts (org_id, status, last_seen_at DESC);
CREATE UNIQUE INDEX alerts_open_dedupe ON alerts (org_id, dedupe_key) WHERE dedupe_key IS NOT NULL AND status <> 'resolved';

-- Application-append-only: the app never updates or deletes entries except retention cleanup.
-- A trigger rejects UPDATE. This does NOT protect against a database administrator.
CREATE TABLE audit_entries (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  org_id uuid,
  actor_type text NOT NULL CHECK (actor_type IN ('user', 'credential', 'system')),
  actor_id text,
  action text NOT NULL,
  target_type text,
  target_id text,
  metadata jsonb NOT NULL DEFAULT '{}'::jsonb,
  created_at timestamptz NOT NULL DEFAULT clock_timestamp()
);
CREATE INDEX audit_org_idx ON audit_entries (org_id, created_at DESC);

CREATE FUNCTION audit_entries_no_update() RETURNS trigger AS $$
BEGIN
  RAISE EXCEPTION 'audit_entries is append-only';
END;
$$ LANGUAGE plpgsql;
CREATE TRIGGER audit_entries_no_update BEFORE UPDATE ON audit_entries
  FOR EACH ROW EXECUTE FUNCTION audit_entries_no_update();

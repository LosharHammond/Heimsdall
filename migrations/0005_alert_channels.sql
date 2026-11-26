-- Alert delivery to Slack and email: channels per organization and an outbox of deliveries with retries.

CREATE TABLE notification_channels (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  org_id uuid NOT NULL REFERENCES organizations (id) ON DELETE CASCADE,
  kind text NOT NULL CHECK (kind IN ('slack', 'email')),
  name text NOT NULL CHECK (length(name) BETWEEN 1 AND 80),
  -- slack: the incoming-webhook URL (encrypted). email: the recipient list (encrypted: addresses are personal data).
  target_enc text NOT NULL,
  target_hint text NOT NULL,
  min_severity text NOT NULL DEFAULT 'medium' CHECK (min_severity IN ('low', 'medium', 'high')),
  kinds text[],
  enabled boolean NOT NULL DEFAULT true,
  created_by uuid REFERENCES users (id),
  created_at timestamptz NOT NULL DEFAULT now(),
  last_success_at timestamptz,
  last_error text,
  last_error_at timestamptz,
  UNIQUE (id, org_id)
);
CREATE INDEX notification_channels_org_idx ON notification_channels (org_id);

CREATE TABLE channel_deliveries (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  org_id uuid NOT NULL,
  channel_id uuid NOT NULL,
  alert_id uuid NOT NULL REFERENCES alerts (id) ON DELETE CASCADE,
  status text NOT NULL DEFAULT 'pending' CHECK (status IN ('pending', 'sent', 'failed', 'dead')),
  attempts integer NOT NULL DEFAULT 0,
  next_attempt_at timestamptz NOT NULL DEFAULT now(),
  last_error text,
  created_at timestamptz NOT NULL DEFAULT now(),
  sent_at timestamptz,
  UNIQUE (channel_id, alert_id),
  FOREIGN KEY (channel_id, org_id) REFERENCES notification_channels (id, org_id) ON DELETE CASCADE
);
CREATE INDEX channel_deliveries_due_idx ON channel_deliveries (status, next_attempt_at);

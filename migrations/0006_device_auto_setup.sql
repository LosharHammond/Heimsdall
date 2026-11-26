-- Automatic device setup: browsers added from the dashboard with one click (Web Push), and companion apps paired with a
-- code confirmed in the dashboard instead of a copied enrollment token.

ALTER TABLE devices ADD COLUMN kind text NOT NULL DEFAULT 'companion' CHECK (kind IN ('companion', 'browser'));
ALTER TABLE devices ADD COLUMN user_id uuid REFERENCES users (id) ON DELETE CASCADE;
ALTER TABLE devices DROP CONSTRAINT IF EXISTS devices_platform_check;
ALTER TABLE devices ADD CONSTRAINT devices_platform_check CHECK (platform IN ('windows', 'linux', 'macos', 'android', 'ios', 'other'));

-- A browser's push subscription (Web Push). One per browser device.
CREATE TABLE push_subscriptions (
  device_id uuid PRIMARY KEY,
  org_id uuid NOT NULL,
  endpoint text NOT NULL,
  p256dh text NOT NULL,
  auth text NOT NULL,
  created_at timestamptz NOT NULL DEFAULT now(),
  last_success_at timestamptz,
  FOREIGN KEY (device_id, org_id) REFERENCES devices (id, org_id) ON DELETE CASCADE
);

-- What was pushed to which browser (an alert or an approval request), once each.
CREATE TABLE push_deliveries (
  device_id uuid NOT NULL REFERENCES devices (id) ON DELETE CASCADE,
  ref text NOT NULL,
  state text NOT NULL CHECK (state IN ('sent', 'failed', 'gone')),
  detail text,
  created_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (device_id, ref)
);

-- Companion pairing: the app asks, a person confirms in the dashboard, the app collects its device key once.
CREATE TABLE device_pairings (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  user_code text NOT NULL UNIQUE,
  poll_secret_hash text NOT NULL,
  device_name text NOT NULL CHECK (length(device_name) BETWEEN 1 AND 120),
  platform text NOT NULL,
  companion_version text NOT NULL,
  request_ip text,
  status text NOT NULL DEFAULT 'pending' CHECK (status IN ('pending', 'approved', 'denied', 'claimed', 'expired')),
  org_id uuid REFERENCES organizations (id) ON DELETE CASCADE,
  device_id uuid REFERENCES devices (id) ON DELETE CASCADE,
  device_key_enc text,
  approved_by uuid REFERENCES users (id),
  created_at timestamptz NOT NULL DEFAULT now(),
  expires_at timestamptz NOT NULL,
  decided_at timestamptz
);
CREATE INDEX device_pairings_expires_idx ON device_pairings (expires_at);

-- Server-generated secrets that must survive restarts (the Web Push key pair). Encrypted with AUTH_ENCRYPTION_KEY.
CREATE TABLE server_secrets (
  name text PRIMARY KEY,
  value_enc text NOT NULL,
  created_at timestamptz NOT NULL DEFAULT now()
);

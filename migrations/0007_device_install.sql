-- One-click computer install from the browser (docs/DEVICES.md).
-- A signed-in person downloads the Windows app; the download carries a one-time code that adds that computer.
CREATE TABLE device_install_tokens (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  token_hash text NOT NULL UNIQUE,
  org_id uuid NOT NULL REFERENCES organizations (id) ON DELETE CASCADE,
  user_id uuid NOT NULL REFERENCES users (id) ON DELETE CASCADE,
  created_at timestamptz NOT NULL DEFAULT now(),
  expires_at timestamptz NOT NULL,
  used_at timestamptz,
  device_id uuid REFERENCES devices (id) ON DELETE SET NULL,
  claim_ip text
);
CREATE INDEX device_install_tokens_org ON device_install_tokens (org_id, created_at DESC);

-- When true, a computer added from a download waits for an administrator (like pairing) instead of being added at once.
ALTER TABLE organizations ADD COLUMN device_approval_required boolean NOT NULL DEFAULT false;

-- When each scheduled job last ran. Lets a short scheduled call (Vercel Cron, GitHub Actions) run the daily jobs only once a day.
CREATE TABLE IF NOT EXISTS job_runs (
  name text PRIMARY KEY,
  last_at timestamptz NOT NULL DEFAULT now()
);

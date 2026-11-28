/** Always available, canonical destinations for the four Kenuxa apps. */
export interface KenuxaApp { client_id: string; name: string; home_url: string; icon_url: string | null }
export const KENUXA_APPS: KenuxaApp[] = [
  {
    "client_id": "accounts",
    "name": "Kenuxa Accounts",
    "home_url": "https://kenuxaaccounts.vercel.app",
    "icon_url": null
  },
  {
    "client_id": "bask",
    "name": "Kenuxa Bask",
    "home_url": "https://kenuxabask.vercel.app",
    "icon_url": null
  },
  {
    "client_id": "heimdall",
    "name": "Kenuxa Heimdall",
    "home_url": "https://kenuxa-heimdall.vercel.app",
    "icon_url": null
  },
  {
    "client_id": "sourcebook",
    "name": "Kenuxa Sourcebook",
    "home_url": "https://kenuxa-sourcebook.vercel.app",
    "icon_url": null
  }
];

/** A partial or stale registry cannot remove or redirect the built-in apps. */
export function mergeKenuxaApps(value: unknown): KenuxaApp[] {
  const rows: KenuxaApp[] = Array.isArray(value) ? value.filter((a): a is KenuxaApp =>
    !!a && typeof a.client_id === 'string' && typeof a.name === 'string' &&
    typeof a.home_url === 'string' && a.home_url.startsWith('https://')) : [];
  return [...KENUXA_APPS.map((a) => ({ ...rows.find((r) => r.client_id === a.client_id), ...a })),
    ...rows.filter((a, i) => !KENUXA_APPS.some((b) => b.client_id === a.client_id) && rows.findIndex((b) => b.client_id === a.client_id) === i)];
}

import { describe, expect, it } from 'vitest'
import { mergeKenuxaApps, KENUXA_APPS } from '../src/shared/kenuxa-apps'

describe('Kenuxa app destinations', () => {
  it('shows all four apps with an empty registry', () => {
    expect(mergeKenuxaApps([]).map((a) => a.client_id)).toEqual(['accounts', 'bask', 'heimdall', 'sourcebook'])
  })
  it('repairs stale destinations and fills a partial registry without duplicates', () => {
    const stale = { ...KENUXA_APPS[2], home_url: 'https://kenuxa-heimdall.onrender.com' }
    const apps = mergeKenuxaApps([stale, stale])
    expect(apps).toHaveLength(4)
    expect(apps.map((a) => a.home_url)).toEqual([
      'https://kenuxaaccounts.vercel.app', 'https://kenuxabask.vercel.app',
      'https://kenuxa-heimdall.vercel.app', 'https://kenuxa-sourcebook.vercel.app',
    ])
  })
})

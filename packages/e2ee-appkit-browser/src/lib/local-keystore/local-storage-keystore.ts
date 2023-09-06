import { DEFAULT_HOURS_UNTIL_EXPIRATION } from '../constants'
import { TimeUtils } from '../utils/time.utils'

interface ValueWrappedWithExpiration {
  value: string
  expiresAt: number
}

export class LocalStorageKeystore {
  constructor() {}

  get(key: string): string | null {
    const got = window.localStorage.getItem(key)
    const deserialized = JSON.parse(got) as ValueWrappedWithExpiration

    if (!deserialized) {
      return null
    }

    if (deserialized.expiresAt < Date.now()) {
      console.log(`Expired key ${key}. Deleting and returning null`)
      this.delete(key)
      return null
    }

    return deserialized.value
  }

  set(key: string, value: string, expiresAt?: number): void {
    if (!expiresAt) {
      expiresAt = TimeUtils.getExpiresAtFromHoursFromNow(DEFAULT_HOURS_UNTIL_EXPIRATION)
    }

    const wrappedValue: ValueWrappedWithExpiration = {
      value,
      expiresAt,
    }

    window.localStorage.setItem(key, JSON.stringify(wrappedValue))
  }

  delete(key: string): void {
    window.localStorage.removeItem(key)
  }
}

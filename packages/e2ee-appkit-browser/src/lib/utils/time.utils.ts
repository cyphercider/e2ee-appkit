import { DEFAULT_HOURS_UNTIL_EXPIRATION } from '../constants'

export class TimeUtils {
  static getExpiresAtFromHoursFromNow(hoursUntilExpiration: number) {
    // 1 hour = 60 minutes = 60 * 60 seconds = 60 * 60 * 1000 milliseconds
    if (!hoursUntilExpiration) {
      hoursUntilExpiration = DEFAULT_HOURS_UNTIL_EXPIRATION
    }

    return Date.now() + hoursUntilExpiration * 60 * 60 * 1000
  }
}

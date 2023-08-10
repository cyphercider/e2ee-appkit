export class TimeUtils {
  public static minutesBeforeNow(ts: number) {
    const now = Date.now()
    if (ts > now) {
      throw new Error(
        `timestamp ${ts} occurs in the future - this function computes duration between a past time and now`,
      )
    }

    const diff = now - ts
    const msPerMinute = 1000 * 60
    return diff / msPerMinute
  }

  static async sleep(ms: number) {
    return new Promise((resolve) => setTimeout(resolve, ms))
  }
}

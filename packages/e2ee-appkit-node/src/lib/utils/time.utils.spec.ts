import { TimeUtils } from './time.utils'

describe('Time utils should work', () => {
  it('should throw if timestamp is in the future', async () => {
    expect(async () => {
      TimeUtils.minutesBeforeNow(99999999999999)
    }).rejects.toThrow()
  })
})

import { NumberUtils } from './number.utils'

describe('number utils should work', () => {
  it('should throw if trying to convert non-numeric value', async () => {
    expect(async () => {
      NumberUtils.toNumber('not a number')
    }).rejects.toThrow()
  })
})

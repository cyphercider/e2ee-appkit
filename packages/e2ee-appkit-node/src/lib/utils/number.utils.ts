export class NumberUtils {
  static isNumber(input: string) {
    return !Number.isNaN(Number(input))
  }

  static toNumber(input: string) {
    if (!this.isNumber(input)) {
      throw new Error(`Can't convert ${input} to a number`)
    }
    return Number(input)
  }
}

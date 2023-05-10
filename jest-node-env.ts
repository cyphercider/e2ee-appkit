// To compensate for missing TextEncoder in jsdom per https://github.com/jsdom/jsdom/issues/2524

import { webcrypto as crypto } from 'crypto'
import { TestEnvironment } from 'jest-environment-node'
import JSDOMEnvironment, { TestEnvironment as TestEnvironmentJsdom } from 'jest-environment-jsdom'

import { TextDecoder as tdimp, TextEncoder as teimp } from 'util'

class CustomNodeEnvironment extends TestEnvironment {
  jsdomEnv: JSDOMEnvironment
  constructor(config: any, context: any) {
    super(config, context)
    this.jsdomEnv = new TestEnvironmentJsdom(config, context)
  }

  async setup() {
    await super.setup()
    const glo = this.global as any

    this.global.process.env['TEST_MODE'] = 'true'

    glo.TextDecoder = tdimp
    glo.TextEncoder = teimp
    glo.window = this.jsdomEnv.global.window

    Object.defineProperty(glo.window, 'crypto', {
      value: crypto,
      writable: true,
      configurable: true,
    })

    glo.document = this.jsdomEnv.global.document
    glo.navigator = this.jsdomEnv.global.navigator
  }
}

export default CustomNodeEnvironment

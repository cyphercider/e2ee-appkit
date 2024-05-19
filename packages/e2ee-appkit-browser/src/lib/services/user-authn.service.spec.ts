import { ServerChallengeResponse } from '@cyphercider/e2ee-appkit-shared-models'
import axios from 'axios'
import { ulid } from 'ulid'
import { ConfigService } from './config.service'
import { CryptoVerificationService } from './crypto-verification.service'
import { CryptoService } from './crypto.service'
import { UserAuthenticationService } from './user-authn.service'

describe('test user authn service', () => {
  let userAuthnService: UserAuthenticationService
  let cryptoService: CryptoService
  let cryptoVerificationService: CryptoVerificationService
  let configService: ConfigService
  // set to false to an end to end test
  beforeEach(() => {
    // Adjust config settings to your test backend if applicable - for running the live test  only
    configService = new ConfigService('http://localhost:3002')
    cryptoService = new CryptoService()
    cryptoVerificationService = new CryptoVerificationService(cryptoService)
    userAuthnService = new UserAuthenticationService(
      configService,
      cryptoService,
      cryptoVerificationService,
    )
  })

  afterEach(() => {
    jest.clearAllMocks()
    // Clear token and keys
    userAuthnService.logout()
  })

  // change 'xit' to 'it' to test against live server
  xit('test signup and login LIVE TEST', async () => {
    const user = ulid()
    const pass = ulid()

    await userAuthnService.signupUser(user, pass, '', '', { defaultCollectionId: ulid() })

    const res = await userAuthnService.login(user, pass)
    expect(res.token).toBeDefined()
  })

  it('test signup and login mocked', async () => {
    // Must be static since we are using a hardcoded challenge response for the mock

    const user = 'static_username'
    const pass = 'static_password'

    expect(async () => {
      userAuthnService.getSessionTokenPayload()
    }).rejects.toThrow(Error) // should throw since token is not present

    userAuthnService['getChallengeFromServer'] = jest.fn().mockResolvedValue(testChallengeResponse)
    userAuthnService['submitChallengeToServer'] = jest
      .fn()
      .mockResolvedValue({ token: testUserJwt, refreshToken: testUserRefreshToken })
    userAuthnService['signupUserOnServer'] = jest.fn().mockResolvedValue({})

    expect(userAuthnService.isLoggedIn).toBeFalsy()

    await userAuthnService.signupUser(user, pass, '', '', { defaultCollectionId: ulid() })

    await userAuthnService.login(user, pass)

    expect(userAuthnService.isLoggedIn).toBeTruthy()

    const decodedToken = userAuthnService.getSessionTokenPayload()
    expect(decodedToken.sub).toEqual('1234567890')

    const decodedRefreshToken = userAuthnService.getRefreshTokenPayload()
    expect(decodedRefreshToken.sub).toEqual('1234567890')
  })

  it('should call signup on server', async () => {
    axios.post = jest.fn().mockResolvedValue({ data: 'value' })

    const res = await userAuthnService['signupUserOnServer']({} as any)
    expect(res).toEqual('value')
  })

  it('should call getChallengeFromServer', async () => {
    axios.post = jest.fn().mockResolvedValue({ data: 'value' })

    const res = await userAuthnService['getChallengeFromServer']('username')

    expect(res).toEqual('value')
  })

  it('should call submitChallengeToServer', async () => {
    axios.post = jest.fn().mockResolvedValue({ data: 'value' })

    const res = await userAuthnService['submitChallengeToServer']({} as any)

    expect(res).toEqual('value')
  })

  it('test failed verify', async () => {
    // Must be static since we are using a hardcoded challenge response for the mock

    const user = 'static_username'
    const pass = 'static_password'

    await expect(async () => {
      userAuthnService.getSessionTokenPayload()
    }).rejects.toThrow(Error) // should throw since token is not present

    userAuthnService['getChallengeFromServer'] = jest.fn().mockResolvedValue(testChallengeResponse)
    userAuthnService['submitChallengeToServer'] = jest.fn().mockResolvedValue(testUserJwt)
    userAuthnService['signupUserOnServer'] = jest.fn().mockResolvedValue({})

    expect(userAuthnService.isLoggedIn).toBeFalsy()

    cryptoVerificationService.TestSigningKeyPair = jest.fn()

    cryptoService.verifySignature = jest.fn().mockImplementation(() => {
      throw new Error()
    })

    await expect(async () => {
      await userAuthnService.signupUser(user, pass, '', '', { defaultCollectionId: ulid() })
    }).rejects.toThrow()
  })

  it('base uri getter', async () => {
    expect(userAuthnService['baseUri']).toEqual(configService.backendHost)
  })

  it('redirect to login', async () => {
    // JSDOM limitation prevents us from testing changes in href
    // https://github.com/facebook/jest/issues/890
    userAuthnService.redirectToLogin()
  })

  it('init current user', async () => {
    userAuthnService.getSessionTokenPayload = jest.fn().mockReturnValue({ sub: 'value' })
    userAuthnService.getSessionToken = jest.fn().mockReturnValue('token')

    userAuthnService['initCurrentUserIfTokenPresent']()
    expect(userAuthnService.currentUser).toEqual({ sub: 'value' })

    userAuthnService.getSessionTokenPayload = jest.fn().mockImplementation(() => {
      throw new Error()
    })

    userAuthnService['clearSessionToken'] = jest.fn()
    userAuthnService['initCurrentUserIfTokenPresent']()
    expect(userAuthnService['clearSessionToken']).toHaveBeenCalled()
  })
})

const testUserJwt =
  'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c' // sub: 1234567890

const testUserRefreshToken =
  'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwicmVmcmVzaFRva2VuIjoiMTIzNDU2Nzg5MCJ9.1JfKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c' // sub: 1234567890

const testChallengeResponse: ServerChallengeResponse = {
  challengeText: 'CHALLENGETEXT-1677856484758',
  publicSigningKey:
    '-----BEGIN PUBLIC KEY-----\n' +
    'MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAvnELKWUr5lsVh+ZbKvxP\n' +
    'Opc4vURo8oQFG2v2K4Ul5JorOdqr3mbc/vNtwtQMixb+iioAoMvrBBMQa9psx+hh\n' +
    'axag0EILDW7IRZDEq2IpEzjufKWg+EglEhRH5gYPqkWy1mNJ7fkTTNhhOiTKPeKy\n' +
    'SZy0BBTbcL0tMf5z3EP7ii71ZGnYqA+icnWC/bnjtUd129qUPyYrbmua277cs9zj\n' +
    'UzBg4DkQqtAdWt3d2/jP0oDWIz00qkD3kU3qxhFy/TsFuybTlQaol9ZB+6Ho9rkD\n' +
    'aNUK3Ujc4y/leY73txE7oTRJVPjQHSDbSmKMwfCpGJiWug7gqAhSIrgsIP0NGAvV\n' +
    'swIDAQAB\n' +
    '-----END PUBLIC KEY-----\n',
  encryptedPrivateSigningKey:
    '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',
  privateSigningKeyInitVector: '01GTM0MB6C1WAAETV0XC7TSA2P',
  publicEncryptionKey:
    '-----BEGIN PUBLIC KEY-----\n' +
    'MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAxQTfDtrUDzfnhE1wxabk\n' +
    '6aG3tKEc200dD/ZQQcuybHgxLQLIa7xwYkAt3PdrIOIdRGJiIhzpebMADVhCyYwe\n' +
    'oDXooTxTBZnWU/xq5MSwSGVPMXm4yVu910jRj9mhTB/LKRwYR6jTyui6fl57jwxU\n' +
    'k+/ySd6sFrIVtZyxJKMkgRHu7CCV8hD+A0HBn3+mJBsAafFXyhxGzg7KCqT23xIa\n' +
    'falWRucFEXpii/y3kDhCs8zS68OwDI3tksXi0l49pJMDx0nz+M1/dLNUVFzi6M/2\n' +
    'Dn3+nwiSdZQb0d818SRCyH8tPP1NyNza74/PaGGDzKIhKWn104zgUOfcfLhWVqeZ\n' +
    'lwIDAQAB\n' +
    '-----END PUBLIC KEY-----\n',
  encryptedPrivateEncryptionKey:
    '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',
  privateEncryptionKeyInitVector: '01GTM0MB5FG30EKR9YSXNH3386',
}

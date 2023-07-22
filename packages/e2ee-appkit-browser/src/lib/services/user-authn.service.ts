import {
  KeyPair,
  KeypairAlgorithm,
  LoginRequestInterface,
  ServerChallengeResponse,
  SignupInterface,
  SubmitChallengeInterface,
  TokenPayload,
  UserInterface,
} from '@cyphercider/e2ee-appkit-shared-models'
import { decodeJwt } from 'jose'
import axios from 'axios'
import { ulid } from 'ulid'
import { ConfigService } from './config.service'
import { CryptoVerificationService } from './crypto-verification.service'
import { CryptoService } from './crypto.service'

export class UserAuthenticationService {
  private _loggedIn: boolean | undefined // True if logged in and keys present - false if not
  public currentUser: TokenPayload // Current user value, initialized after login

  constructor(
    private readonly configService: ConfigService,
    private readonly cryptoService: CryptoService,
    private readonly cryptoVerificationService: CryptoVerificationService,
  ) {
    this.initCurrentUserIfTokenPresent()
  }

  /**
   * ********************************* Public methods ******************************
   */

  /**
   * Whether or not the user is logged in
   * This means that the session token is present in local storage, and both the signing and encryption keypairs are present in session_storage
   */
  public get isLoggedIn() {
    if (this._loggedIn === undefined) {
      // If reloading the browser, test if keys are still present from a previous session
      this._loggedIn = this.sessionTokenPresent && this.cryptoService.allKeysArePresent
    }
    return this._loggedIn
  }

  /**
   * Redirect the browser user to the login endpoint
   */
  public redirectToLogin() {
    this.clearSessionToken()
    window.location.href = window.location.origin + this.configService.loginFrontendRoute
  }

  /**
   * Get the session token from local storage and return its decoded contents
   */
  public getSessionTokenPayload(): TokenPayload {
    const token = this.getSessionToken()
    if (!token) throw new Error('Session token is falsy - cannot get decoded token')
    return decodeJwt(token) as TokenPayload
  }

  /**
   * Get the session token (JWT) from local storage
   */
  public getSessionToken() {
    return window.localStorage.getItem('session_token')
  }

  /**
   * Login to the server with username and password
   */
  public async login(username: string, password: string): Promise<ServerChallengeResponse> {
    const challengeResponse = await this.getChallengeFromServer(username)

    this.cryptoService.setPublicEncryptionKey(challengeResponse.publicEncryptionKey)
    this.cryptoService.setPublicSigningKey(challengeResponse.publicSigningKey)

    const unwrappedEncKey = await this.cryptoService.decryptTextWithPassword(
      password,
      challengeResponse.encryptedPrivateEncryptionKey,
      challengeResponse.privateEncryptionKeyInitVector,
      username,
    )

    const unwrappedSigningKey = await this.cryptoService.decryptTextWithPassword(
      password,
      challengeResponse.encryptedPrivateSigningKey,
      challengeResponse.privateSigningKeyInitVector,
      username,
    )

    this.cryptoService.setPrivateEncryptionKey(unwrappedEncKey)
    this.cryptoService.setPrivateSigningKey(unwrappedSigningKey)

    const pubSign = this.cryptoService.getPublicSigningKey()
    const privSign = this.cryptoService.getPrivateSigningKey()

    // Verify keypair integrity
    await this.cryptoVerificationService.TestSigningKeyPair(
      pubSign,
      privSign,
      challengeResponse.challengeText,
    )

    const signed = await this.cryptoService.signContent(challengeResponse.challengeText, privSign)

    try {
      // Verify signature integrity before sending to server
      await this.cryptoService.verifySignature(
        signed.signature,
        signed.protected,
        pubSign,
        challengeResponse.challengeText,
      )
    } catch (err) {
      console.error(`error in signing verification in AuthN service`, err)
      throw err
    }

    const submission: SubmitChallengeInterface = {
      username,
      protected: signed.protected,
      challengeText: challengeResponse.challengeText,
      signature: signed.signature,
    }

    const res = await this.submitChallengeToServer(submission)

    this.setSessionToken(res)
    this.currentUser = { sub: username, ...this.getSessionTokenPayload() }
    this._loggedIn = true

    return challengeResponse
  }

  /**
   * Signup a new user on the server
   *
   * @param additionalPayloadFields - optional fields to pass to the server on signup if your implementation requires it
   */
  public async signupUser(
    username: string,
    password: string,
    additionalPayloadFields?: Record<string, string>,
    encryptingKeypair?: KeyPair,
    signingKeyPair?: KeyPair,
  ): Promise<ServerChallengeResponse> {
    if (!encryptingKeypair) {
      encryptingKeypair = await this.cryptoService.generateKeyPair(KeypairAlgorithm.Encrypting)
    }
    this.cryptoService.setPrivateEncryptionKey(encryptingKeypair.privateKey)

    if (!signingKeyPair) {
      signingKeyPair = await this.cryptoService.generateKeyPair(KeypairAlgorithm.Signing)
    }
    await this.cryptoVerificationService.TestSigningKeyPair(
      signingKeyPair.publicKey,
      signingKeyPair.privateKey,
      'challenge',
    )
    this.cryptoService.setPrivateSigningKey(signingKeyPair.privateKey)

    const encryptionKeyIv = ulid()
    const wrappedEncryptionPrivKey = await this.cryptoService.encryptTextWithPassword(
      password,
      encryptingKeypair.privateKey,
      encryptionKeyIv,
      username,
    )

    const signingKeyIv = ulid()
    const wrappedSigningPrivKey = await this.cryptoService.encryptTextWithPassword(
      password,
      signingKeyPair.privateKey,
      signingKeyIv,
      username,
    )

    // Create user remotely
    await this.signupUserOnServer({
      username: username,
      publicSigningKey: signingKeyPair.publicKey,
      encryptedPrivateSigningKey: wrappedSigningPrivKey,
      privateSigningKeyInitVector: signingKeyIv,
      publicEncryptionKey: encryptingKeypair.publicKey,
      encryptedPrivateEncryptionKey: wrappedEncryptionPrivKey,
      privateEncryptionKeyInitVector: encryptionKeyIv,
      ...(additionalPayloadFields || {}),
    })

    // login to get token for subsequent api calls
    return await this.login(username, password)
  }

  /**
   * Clear session tokens and keys
   */
  public logout() {
    this.clearSessionToken()
    this.cryptoService.clearEncryptionKeys()
  }

  /**
   * ************************* Private methods **************************
   */

  /**
   * When rehydrating a session - initialize current user with contents of existing token
   */
  private initCurrentUserIfTokenPresent() {
    if (typeof window === 'undefined') return // For nextjs static build

    try {
      if (this.sessionTokenPresent) {
        this.currentUser = this.getSessionTokenPayload()
      }
    } catch (err) {
      console.warn(`Error decoding session token payload - clearing session token`)
      this.clearSessionToken()
    }
  }

  private get baseUri() {
    return this.configService.backendHost
  }

  private get sessionTokenPresent(): boolean {
    return !!this.getSessionToken()
  }

  private setSessionToken(token: string) {
    window.localStorage.setItem('session_token', token)
  }

  private async signupUserOnServer(signupUser: SignupInterface): Promise<UserInterface> {
    const res = await axios.post<UserInterface>(
      `${this.baseUri}${this.configService.signupRoute}`,
      signupUser,
    )
    return res.data
  }

  /**
   * Part 1 of the login process.  Should return a new challenge to be signed by the user's private signing key.
   */
  private async getChallengeFromServer(username: string): Promise<ServerChallengeResponse> {
    const body: LoginRequestInterface = { username }
    const baseUri = this.baseUri

    // Get challenge and basic user info
    const res = await axios.post<ServerChallengeResponse>(
      `${baseUri}${this.configService.challengeRetrieveRoute}`,
      body,
    )
    return res.data
  }

  /**
   * Part 2 of the login process - submit the signed challenge to the server.  If successful, the server should respond with a new user token (JWT)
   */
  private async submitChallengeToServer(submission: SubmitChallengeInterface): Promise<string> {
    const res = await axios.post(
      `${this.baseUri}${this.configService.challengeSubmitRoute}`,
      submission,
    )
    return res.data
  }

  private clearSessionToken() {
    window.localStorage.removeItem('session_token')
  }
}

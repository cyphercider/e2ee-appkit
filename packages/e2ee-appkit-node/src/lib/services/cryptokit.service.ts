import {
  KeypairAlgorithm,
  ServerChallengeResponse,
  SignedServerChallengeResponse,
  SubmitChallengeInterface,
  SubmitChallengeInterfaceWithServerSignature,
  TokenPayload,
  UserInterface,
} from '@cyphercider/e2ee-appkit-shared-models'
import { Buffer } from 'buffer'
import { createHash } from 'crypto'
import { flattenedVerify, importSPKI, KeyLike } from 'jose'
import { NumberUtils, TimeUtils } from '../utils'
import { CryptoUtils } from './crypto-test.service'

const CHALLENGE_TEXT_PREFIX = 'CHALLENGETEXT-'

export class CryptoKit {
  /**
   * ************************** Public methods *************************
   */

  /**
   * Given a user object, return a login response object (to return to a user when they request to log in).  The response object contains public and private key information the user will then decrypt in their browser an use to sign the challenge.
   *
   * @param user - The user object you have already persisted on your server.
   * @param transformChallenge - A function that takes the challenge string transforms it (such as creating a signed JWT to allow making sure it is genuine before verifying it)
   * @deprecated - Use getSignedChallenge instead for better security
   */
  public static async getChallenge(user: UserInterface): Promise<ServerChallengeResponse> {
    const challengeText = CHALLENGE_TEXT_PREFIX + Date.now()

    const res: ServerChallengeResponse = {
      challengeText,
      publicSigningKey: user.publicSigningKey,
      encryptedPrivateSigningKey: user.encryptedPrivateSigningKey,
      encryptedPrivateSigningKeyAlternate: user.encryptedPrivateSigningKeyAlternate,
      privateSigningKeyInitVector: user.privateSigningKeyInitVector,
      publicEncryptionKey: user.publicEncryptionKey,
      encryptedPrivateEncryptionKey: user.encryptedPrivateEncryptionKey,
      encryptedPrivateEncryptionKeyAlternate: user.encryptedPrivateEncryptionKeyAlternate,
      privateEncryptionKeyInitVector: user.privateEncryptionKeyInitVector,
    }

    return res
  }

  /**
   * Given a user object, return a login response object (to return to a user when they request to log in).  The response object contains public and private key information the user will then decrypt in their browser an use to sign the challenge.
   *
   * @param user - The user object you have already persisted on your server.
   * @param signingFunction - A function that takes the challenge string transforms it (such as creating a signed JWT to allow making sure it is genuine before verifying it)
   */
  public static async getSignedChallenge(
    user: UserInterface,
    privateSigningKey: string,
  ): Promise<SignedServerChallengeResponse> {
    const challengeText = CHALLENGE_TEXT_PREFIX + Date.now()

    const signatureResult = await CryptoUtils.signContent(challengeText, privateSigningKey)

    const res: SignedServerChallengeResponse = {
      challengeText,
      publicSigningKey: user.publicSigningKey,
      encryptedPrivateSigningKey: user.encryptedPrivateSigningKey,
      encryptedPrivateSigningKeyAlternate: user.encryptedPrivateSigningKeyAlternate,
      privateSigningKeyInitVector: user.privateSigningKeyInitVector,
      publicEncryptionKey: user.publicEncryptionKey,
      encryptedPrivateEncryptionKey: user.encryptedPrivateEncryptionKey,
      encryptedPrivateEncryptionKeyAlternate: user.encryptedPrivateEncryptionKeyAlternate,
      privateEncryptionKeyInitVector: user.privateEncryptionKeyInitVector,
      serverProtected: signatureResult.protected,
      serverSignature: signatureResult.signature,
    }

    return res
  }

  /**
   * @param additionalTokenAttributes - Additional attributes to include in your token payload if needed
   * @param maxAllowedChallengeAgeMins - Override the default max age of a challenge (10 mins)
   * @param serverPublicSigningKey - The public key of the server that signed the challenge. Verifies the server generated the challenge and not some other party.
   * @param BadRequestException - thrown if the request is malformed (would be HTTP status code 400).  Provide your own exception class if desired (e.g. a specialized HTTP exception).  Otherwise, a generic Error will be thrown.
   * @param ForbiddenException - The exception thrown if the signature is invalid (would be HTTP status code 403).  Provide your own exception class if desired (e.g. a specialized HTTP exception).  Otherwise, a generic Error will be thrown.
   *
   * @returns - token payload to sign (to create user token)
   */
  static async submitChallengeWithServerSignature(
    submit: SubmitChallengeInterfaceWithServerSignature,
    user: UserInterface,
    serverPublicSigningKey: string,
    additionalTokenAttributes: Record<string, string> = {},
    maxAllowedChallengeAgeMins = 10,
    BadRequestException = Error,
    ForbiddenException = Error,
  ): Promise<TokenPayload> {
    // verify server signature
    await this.verifySignature(
      submit.serverSignature,
      submit.serverProtected,
      serverPublicSigningKey,
      submit.challengeText,
    )

    return this.submitChallenge(
      submit,
      user,
      additionalTokenAttributes,
      maxAllowedChallengeAgeMins,
      BadRequestException,
      ForbiddenException,
    )
  }

  /**
   * @param additionalTokenAttributes - Additional attributes to include in your token payload if needed
   * @param maxAllowedChallengeAgeMins - Override the default max age of a challenge (10 mins)
   * @param BadRequestException - thrown if the request is malformed (would be HTTP status code 400).  Provide your own exception class if desired (e.g. a specialized HTTP exception).  Otherwise, a generic Error will be thrown.
   * @param ForbiddenException - The exception thrown if the signature is invalid (would be HTTP status code 403).  Provide your own exception class if desired (e.g. a specialized HTTP exception).  Otherwise, a generic Error will be thrown.
   *
   * @returns - token payload to sign (to create user token)
   *
   * @deprecated - Use submitChallengeWithServerSignature instead for better security
   */
  public static async submitChallenge(
    submit: SubmitChallengeInterface,
    user: UserInterface,
    additionalTokenAttributes: Record<string, string> = {},
    maxAllowedChallengeAgeMins = 10,
    BadRequestException = Error,
    ForbiddenException = Error,
  ): Promise<TokenPayload> {
    const split = submit.challengeText.split('-')
    if (split.length !== 2) {
      throw new BadRequestException(
        `malformed challenge response - must be two strings separated by an -`,
      )
    }

    if (!NumberUtils.isNumber(split[1])) {
      throw new Error(`Second half of challenge text, ${split[1]}, must be a numeric timestamp!`)
    }

    const ts = NumberUtils.toNumber(split[1])
    const minutesDiff = TimeUtils.minutesBeforeNow(ts)
    if (minutesDiff > maxAllowedChallengeAgeMins) {
      throw new BadRequestException(
        `Challenge is too old (${minutesDiff} minutes).  Please retry login.`,
      )
    }

    try {
      await this.verifySignature(
        submit.signature,
        submit.protected,
        user.publicSigningKey,
        submit.challengeText,
      )
    } catch (err) {
      throw new ForbiddenException(`Signature verification failed ${err.message}`)
    }

    return {
      sub: user.username,
      ...additionalTokenAttributes,
    }
  }

  /**
   * Given a public key and a signed piece of content, validate the signature
   *
   * @param signature - the serialized signature provided by the signer
   * @param protectedStr - The `protected` value output by the signature process.
   * @param pubkey - The serialized public key of the signer.
   * @param content - The content that was signed.
   */
  public static async verifySignature(
    signature: string,
    protectedStr: string,
    pubkey: string,
    content: string,
  ) {
    const imported = await this.importPubKey(pubkey, KeypairAlgorithm.Signing)

    const payloadHash = await this.getSha256hash(content)
    const buff = Buffer.from(payloadHash, 'utf-8')
    const base64 = buff.toString('base64').replaceAll('=', '')

    const res = await flattenedVerify(
      { payload: base64, signature: signature, protected: protectedStr },
      imported,
    )

    return res
  }

  /**
   * ************************ Private methods ****************************
   */

  private static async importPubKey(
    pubKeyString: string,
    algo: KeypairAlgorithm,
  ): Promise<KeyLike> {
    return await importSPKI(pubKeyString, algo)
  }

  private static async getSha256hash(input: string) {
    return createHash('sha256').update(input).digest('base64')
  }
}

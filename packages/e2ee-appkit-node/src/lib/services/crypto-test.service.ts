import {
  KeyPair,
  KeypairAlgorithm,
  SignatureResult,
  UserInterface,
} from '@cyphercider/e2ee-appkit-shared-models'
import { exportPKCS8, exportSPKI, FlattenedSign, importPKCS8, KeyLike, generateKeyPair } from 'jose'
import { ulid } from 'ulid'

import { createHash } from 'crypto'

export class TestUtils {
  /**
   * Generate keypair for testing
   */
  public static async generateKeyPair(algo: KeypairAlgorithm): Promise<KeyPair> {
    const res = await generateKeyPair(algo, { extractable: true })

    const ret: KeyPair = {
      publicKey: await exportSPKI(res.publicKey),
      privateKey: await exportPKCS8(res.privateKey),
      gcmInitVector: ulid(),
    }

    return ret
  }

  /**
   * Sign content with a private key
   *
   * @param privateKey - Private key (serialized) to use for signing
   * @param content - string content to sign
   */
  public static async signContent(content: string, privateKey: string): Promise<SignatureResult> {
    const privKeyImported = await this.importPrivateKey(privateKey, KeypairAlgorithm.Signing)
    return this.signTextWithPrivateKeyRaw(content, privKeyImported)
  }

  private static async signTextWithPrivateKeyRaw(
    payload: string,
    privKey: KeyLike,
  ): Promise<SignatureResult> {
    const payloadHash = await this.getSha256hash(payload)

    const res = await new FlattenedSign(new TextEncoder().encode(payloadHash))
      .setProtectedHeader({ alg: KeypairAlgorithm.Signing })
      .sign(privKey)

    return {
      signature: res.signature,
      protected: res.protected,
      payload: res.payload,
    }
  }

  private static async importPrivateKey(
    privKeyString: string,
    algo: KeypairAlgorithm,
  ): Promise<KeyLike> {
    return importPKCS8(privKeyString, algo)
  }

  /**
   * ************** Utils *****************
   */

  private static async getSha256hash(input: string) {
    return createHash('sha256').update(input).digest('base64')
  }

  static async generateTestUser(): Promise<UserInterface> {
    const encryptingKey = await this.generateKeyPair(KeypairAlgorithm.Encrypting)
    const signingKey = await this.generateKeyPair(KeypairAlgorithm.Signing)

    return {
      username: 'username',
      publicSigningKey: signingKey.publicKey,
      encryptedPrivateSigningKey: signingKey.privateKey, // intentionally not encrypting for this test
      privateSigningKeyInitVector: signingKey.gcmInitVector,
      publicEncryptionKey: encryptingKey.publicKey, // intentionally not encrypting for this test
      privateEncryptionKeyInitVector: encryptingKey.privateKey,
      encryptedPrivateEncryptionKey: encryptingKey.gcmInitVector,
    }
  }
}

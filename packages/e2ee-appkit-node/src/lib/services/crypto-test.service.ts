import {
  KeyPair,
  KeypairAlgorithm,
  SignatureResult,
  UserInterface,
} from '@cyphercider/e2ee-appkit-shared-models'
import {
  exportPKCS8,
  exportSPKI,
  FlattenedSign,
  importPKCS8,
  KeyLike,
  generateKeyPair,
  flattenedVerify,
  importSPKI,
} from 'jose'
import { ulid } from 'ulid'

import { createHash } from 'crypto'

export class CryptoUtils {
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

  /**
   * ************************ Private methods ****************************
   */

  private static async importPubKey(
    pubKeyString: string,
    algo: KeypairAlgorithm,
  ): Promise<KeyLike> {
    return await importSPKI(pubKeyString, algo)
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
    }
  }

  /**
   * Verify a private key signature with the public key
   */
  public static async verifySignature(
    signature: string,
    protectedStr: string,
    pubkey: string,
    content: string,
  ) {
    const imported = await this.importPubKey(pubkey, KeypairAlgorithm.Signing)

    return await this.verifySignatureRaw(signature, protectedStr, imported, content)
  }

  private static async verifySignatureRaw(
    signature: string,
    protectedStr: string,
    pubkey: KeyLike,
    content: string,
  ) {
    const payloadHash = await this.getSha256hash(content)
    const buff = Buffer.from(payloadHash, 'utf-8')
    const base64 = buff.toString('base64').replaceAll('=', '')

    console.log('*** computed hash base64: ', base64)

    const res = await flattenedVerify(
      { payload: base64, signature: signature, protected: protectedStr },
      pubkey,
    )

    return res
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
}

export class TestUtils {
  static async generateTestUser(): Promise<UserInterface> {
    const encryptingKey = await CryptoUtils.generateKeyPair(KeypairAlgorithm.Encrypting)
    const signingKey = await CryptoUtils.generateKeyPair(KeypairAlgorithm.Signing)

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

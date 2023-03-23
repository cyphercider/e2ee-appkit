import { KeypairAlgorithm } from '@cyphercider/e2ee-appkit-shared-models'
import { ulid } from 'ulid'
import { CryptoService } from './crypto.service'

/**
 * Utilities to verify the integrity of a public / private signing keypair
 */
export class CryptoVerificationService {
  constructor(private readonly cryptoService: CryptoService) {}

  async TestSigningKeyPair(pubKeyString: string, privKeyString: string, challenge: string) {
    try {
      const signature = await this.cryptoService.signContent(challenge, privKeyString)

      await this.cryptoService.verifySignature(
        signature.signature,
        signature.protected,
        pubKeyString,
        challenge,
      )
    } catch (error) {
      console.error(`Error verifying signing keypair`, error)
      throw error
    }
  }

  async TestSignatureWithNewKey(challenge: string) {
    try {
      const key = await this.cryptoService.generateKeyPair(KeypairAlgorithm.Signing)

      const signature = await this.cryptoService.signContent(challenge, key.privateKey)

      await this.cryptoService.verifySignature(
        signature.signature,
        signature.protected,
        key.publicKey,
        challenge,
      )
    } catch (error) {
      console.error(`Error with test verify in signup`, error)
      throw new Error(error.message)
    }
  }
}

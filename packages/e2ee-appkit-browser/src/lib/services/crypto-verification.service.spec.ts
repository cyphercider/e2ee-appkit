import { KeypairAlgorithm } from '@cyphercider/e2ee-appkit-shared-models'
import { ulid } from 'ulid'

import { CryptoVerificationService } from './crypto-verification.service'
import { CryptoService } from './crypto.service'

describe('crypto verification service', () => {
  let cryptoService: CryptoService
  let cryptoVerificationService: CryptoVerificationService
  beforeEach(() => {
    jest.clearAllMocks()
    cryptoService = new CryptoService()
    cryptoVerificationService = new CryptoVerificationService(cryptoService)
  })
  it('should test signature with new key', async () => {
    await cryptoVerificationService.TestSignatureWithNewKey(ulid())
  })

  it('should test sign with provided key', async () => {
    const keyPair = await cryptoService.generateKeyPair(KeypairAlgorithm.Encrypting)
    await cryptoVerificationService.TestSigningKeyPair(
      keyPair.publicKey,
      keyPair.privateKey,
      ulid(),
    )
  })

  it('should throw error for signing key pair', async () => {
    await expect(async () => {
      await cryptoVerificationService.TestSigningKeyPair(ulid(), ulid(), '')
    }).rejects.toThrow()
  })

  it('should throw error for test signature with new key', async () => {
    await expect(async () => {
      await cryptoVerificationService.TestSignatureWithNewKey(undefined as '')
    }).rejects.toThrow()
  })
})

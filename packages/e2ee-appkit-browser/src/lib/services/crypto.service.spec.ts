import { ulid } from 'ulid'
import { CryptoService } from './crypto.service'
import { KeypairAlgorithm } from '@cyphercider/e2ee-appkit-shared-models'

describe('crypto service', () => {
  let cryptoService: CryptoService
  beforeEach(() => {
    cryptoService = new CryptoService()
  })
  it('test import / export / sign for crypto key', async () => {
    const key = await cryptoService.generateKeyPair(KeypairAlgorithm.Signing)

    const challengeText = ulid()

    const signed = await cryptoService.signContent(challengeText, key.privateKey)

    await cryptoService.verifySignature(
      signed.signature,
      signed.protected,
      key.publicKey,
      challengeText,
    )
  })

  it('should encrypt and decrypt with public/private key', async () => {
    const challengeContent = ulid()
    const userKey = await cryptoService.generateKeyPair(KeypairAlgorithm.Encrypting)

    const encryptedJwe = await cryptoService.encryptWithPublicKey(
      challengeContent,
      userKey.publicKey,
    )

    const decrypted = await cryptoService.decryptWithPrivateKey(encryptedJwe, userKey.privateKey)

    expect(decrypted).toEqual(challengeContent)
  })

  it('test import / export / wrap / unwrap / sign for crypto key', async () => {
    const userpass = ulid()

    const key = await cryptoService.generateKeyPair(KeypairAlgorithm.Signing)

    const wrappedPrivKey = await cryptoService.encryptTextWithPassword(
      userpass,
      key.privateKey,
      key.gcmInitVector,
      'username',
    )

    const unwrappedPrivKey = await cryptoService.decryptTextWithPassword(
      userpass,
      wrappedPrivKey,
      key.gcmInitVector,
      'username',
    )

    const challengeText = ulid()

    const signed = await cryptoService.signContent(challengeText, unwrappedPrivKey)

    await cryptoService.verifySignature(
      signed.signature,
      signed.protected,
      key.publicKey,
      challengeText,
    )
  })

  it('should wrap text with password', async () => {
    const plaintext = 'thetext'
    const password = 'password'
    const iv = ulid()

    const wrapped = await cryptoService.encryptTextWithPassword(password, plaintext, iv, 'username')
    const unwrapped = await cryptoService.decryptTextWithPassword(password, wrapped, iv, 'username')

    expect(unwrapped).toEqual(plaintext)
  })

  it('should fail verification', async () => {
    const key = await cryptoService.generateKeyPair(KeypairAlgorithm.Signing)

    const challengeText = ulid()
    const signed = await cryptoService.signContent(challengeText, key.privateKey)

    await expect(async () => {
      await cryptoService.verifySignature(signed.signature, signed.protected, key.publicKey, 'junk')
    }).rejects.toThrow()
  })

  it('should create symmetric key and encrypt / decrypt with it', async () => {
    const key = await cryptoService.generateSymmetricKey()
    const iv = ulid()
    const secret = 'thesecret'
    const encrypted = await cryptoService.encryptWithSymmetricKey(key, secret, iv)
    const decrypted = await cryptoService.decryptWithSymmetricKey(key, encrypted, iv)
    expect(decrypted).toEqual(secret)
  })

  it('should encrypt and decrypt object with symmetric key', async () => {
    const key = await cryptoService.generateSymmetricKey()
    const iv = ulid()
    const plainText = 'plain test value'
    const toEncrypt = 'to encrypt value'
    const obj = {
      plainText,
      toEncrypt,
    }

    await cryptoService.encryptSpecifiedFields(obj, key, iv, ['toEncrypt'])
    expect(obj.plainText).toEqual(plainText)
    expect(obj.toEncrypt).not.toEqual(toEncrypt)

    await cryptoService.decryptSpecifiedFields(obj, key, iv, ['toEncrypt'])
    expect(obj.plainText).toEqual(plainText)
    expect(obj.toEncrypt).toEqual(toEncrypt)
  })

  it('should store, retrieve, and clear keys', async () => {
    const pubEncrypting = 'public encrypting'
    const privEncrypting = 'private encrypting'
    const pubSigning = 'public signing'
    const privSigning = 'private signing'

    cryptoService.setPublicEncryptionKey(pubEncrypting)
    cryptoService.setPrivateEncryptionKey(privEncrypting)
    cryptoService.setPublicSigningKey(pubSigning)
    // Only 3 of 4 keys are set
    expect(cryptoService.allKeysArePresent).toBeFalsy()
    cryptoService.setPrivateSigningKey(privSigning)

    const one = cryptoService.getPublicEncryptionKey()
    const two = cryptoService.getPrivateEncryptionKey()
    const three = cryptoService.getPublicSigningKey()
    const four = cryptoService.getPrivateSigningKey()

    expect(one).toEqual(pubEncrypting)
    expect(two).toEqual(privEncrypting)
    expect(three).toEqual(pubSigning)
    expect(four).toEqual(privSigning)

    expect(cryptoService.allKeysArePresent).toBeTruthy()
    cryptoService.clearEncryptionKeys()
    expect(cryptoService.allKeysArePresent).toBeFalsy()

    const five = cryptoService.getPublicEncryptionKey()
    const six = cryptoService.getPrivateEncryptionKey()
    const seven = cryptoService.getPublicSigningKey()
    const eight = cryptoService.getPrivateSigningKey()

    expect(five).toBeFalsy()
    expect(six).toBeFalsy()
    expect(seven).toBeFalsy()
    expect(eight).toBeFalsy()
  })
})

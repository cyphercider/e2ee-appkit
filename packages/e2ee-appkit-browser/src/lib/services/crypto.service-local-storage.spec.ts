import { ulid } from 'ulid'
import { CryptoService, KeyStoreType } from './crypto.service'
import { KeypairAlgorithm } from '@cyphercider/e2ee-appkit-shared-models'

async function sleep(ms: number) {
  return new Promise((resolve) => setTimeout(resolve, ms))
}

describe('crypto service', () => {
  let cryptoService: CryptoService
  beforeEach(() => {
    cryptoService = new CryptoService(KeyStoreType.LocalStorage)
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

    const encrypted = await cryptoService.encryptSpecifiedFields(obj, key, iv, ['toEncrypt'])
    expect(encrypted.plainText).toEqual(plainText)
    expect(encrypted.toEncrypt).not.toEqual(toEncrypt)

    const decrypted = await cryptoService.decryptSpecifiedFields(encrypted, key, iv, ['toEncrypt'])
    expect(decrypted.plainText).toEqual(plainText)
    expect(decrypted.toEncrypt).toEqual(toEncrypt)
  })

  it('should encrypt inner objects recursively', async () => {
    const obj = {
      field1: 'field1',
      field2: {
        field3: 'field3',
        field4: {
          field5: 'field5',
        },
      },
      arrayField1: [
        {
          field1: 'field1val1',
          field2: {
            field3: 'field3val1',
            field4: {
              field5: 'field5val1',
            },
          },
        },
        {
          field1: 'field1val2',
          field2: {
            field3: 'field3val2',
            field4: {
              field5: 'field5val2',
            },
          },
        },
      ],
    }

    const key = await cryptoService.generateSymmetricKey()
    const iv = ulid()

    //     await cryptoService.encryptSpecifiedFields(obj, key, iv, ['field1', 'field2'])
    const encrypted = await cryptoService.encryptSpecifiedFields(obj, key, iv, [
      'field1',
      'field2',
      'arrayField1',
    ])

    console.log('after encrypt:')
    console.log(JSON.stringify(encrypted, null, 2))

    const decrypted = await cryptoService.decryptSpecifiedFields(encrypted, key, iv, [
      'field1',
      'field2',
      'arrayField1',
    ])

    console.log('after decrypt:')
    console.log(JSON.stringify(decrypted, null, 2))

    expect(decrypted.field1).toEqual('field1')
    expect(decrypted.field2.field3).toEqual('field3')
    expect(decrypted.field2.field4.field5).toEqual('field5')
  })

  it('should not encrypt blank fields', async () => {
    const key = await cryptoService.generateSymmetricKey()
    const iv = ulid()
    const field1 = ''
    const field2 = ulid()
    const field3 = ulid()
    const obj = {
      field1,
      field2,
      field3,
    }

    const fieldsToEncrypt = ['field1', 'field2', 'field3']

    const encrypted = await cryptoService.encryptSpecifiedFields(obj, key, iv, fieldsToEncrypt)
    expect(encrypted.field1).toEqual(field1)
    expect(encrypted.field2).not.toEqual(field2)
    expect(encrypted.field3).not.toEqual(field3)

    const decrypted = await cryptoService.decryptSpecifiedFields(
      encrypted,
      key,
      iv,
      fieldsToEncrypt,
    )
    expect(decrypted.field1).toEqual(field1)
    expect(decrypted.field2).toEqual(field2)
    expect(decrypted.field3).toEqual(field3)
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

  it('expiration time should behave correctly', async () => {
    const expirationIntervalMs = 30
    const expirationIntervalHours = expirationIntervalMs / 1000 / 60 / 60

    cryptoService.setPrivateEncryptionKey('private encrypting', expirationIntervalHours)
    cryptoService.setPublicEncryptionKey('public encrypting', expirationIntervalHours)
    cryptoService.setPrivateSigningKey('private signing', expirationIntervalHours)
    cryptoService.setPublicSigningKey('public signing', expirationIntervalHours)

    expect(cryptoService.allKeysArePresent).toBeTruthy()
    expect(cryptoService.getPrivateEncryptionKey()).toBeTruthy()
    expect(cryptoService.getPublicEncryptionKey()).toBeTruthy()
    expect(cryptoService.getPrivateSigningKey()).toBeTruthy()
    expect(cryptoService.getPublicSigningKey()).toBeTruthy()

    await sleep(expirationIntervalMs + 5)
    console.log(`ok - next step`)

    expect(cryptoService.allKeysArePresent).toBeFalsy()
    expect(cryptoService.getPrivateEncryptionKey()).toBeFalsy()
    expect(cryptoService.getPublicEncryptionKey()).toBeFalsy()
    expect(cryptoService.getPrivateSigningKey()).toBeFalsy()
    expect(cryptoService.getPublicSigningKey()).toBeFalsy()
  })
})

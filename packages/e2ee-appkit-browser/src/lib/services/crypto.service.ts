import {
  exportPKCS8,
  exportSPKI,
  flattenedDecrypt,
  FlattenedEncrypt,
  FlattenedJWE,
  FlattenedSign,
  flattenedVerify,
  generateKeyPair,
  importPKCS8,
  importSPKI,
  KeyLike,
} from 'jose'

import { createHash } from 'crypto-browserify'

import { Buffer } from 'buffer'
import { ulid } from 'ulid'
import SessionKeystore from 'session-keystore'
import { KeyPair, KeypairAlgorithm, SignatureResult } from '@cyphercider/e2ee-appkit-shared-models'

export enum KeyIndexes {
  private_signing_key = 'private_signing_key',
  public_encryption_key = 'public_encryption_key',
  private_encryption_key = 'private_encryption_key',
  public_signing_key = 'public_signing_key',
}

export class CryptoService {
  keyStore = new SessionKeystore()

  /**
   * Clear all encryption keypairs from browser storage - e.g. on logout
   */
  public clearEncryptionKeys() {
    this.keyStore.delete(KeyIndexes.private_encryption_key)
    this.keyStore.delete(KeyIndexes.public_encryption_key)
    this.keyStore.delete(KeyIndexes.private_signing_key)
    this.keyStore.delete(KeyIndexes.public_signing_key)
  }

  /**
   * Returns true if all keypairs are present (both signing and encrypting keypairs).  False otherwise.
   */
  get allKeysArePresent() {
    return (
      !!this.getPrivateEncryptionKey() &&
      !!this.getPublicEncryptionKey() &&
      !!this.getPrivateSigningKey() &&
      !!this.getPublicSigningKey()
    )
  }

  /**
   * ****************** Public Methods ***********************
   */

  /**
   * Sign content with a private key
   *
   * @param privateKey - Private key (serialized) to use for signing
   * @param content - string content to sign
   */
  public async signContent(content: string, privateKey: string): Promise<SignatureResult> {
    const privKeyImported = await this.importPrivateKey(privateKey, KeypairAlgorithm.Signing)
    return this.signTextWithPrivateKeyRaw(content, privKeyImported)
  }

  /**
   * Verify a private key signature with the public key
   */
  public async verifySignature(
    signature: string,
    protectedStr: string,
    pubkey: string,
    content: string,
  ) {
    const imported = await this.importPubKey(pubkey, KeypairAlgorithm.Signing)

    return await this.verifySignatureRaw(signature, protectedStr, imported, content)
  }

  /**
   * Encrypt some content with a public key.
   * Can be decrypted later with the matching private key.
   *
   * @param content - Data to encrypt
   * @param publicKey - Public key (serialized)
   *
   * @returns - a jose FlattenedJWE object serialized as a string (stringified)
   */
  public async encryptWithPublicKey(content: string, publicKey: string): Promise<string> {
    const key = await this.importPubKey(publicKey, KeypairAlgorithm.Encrypting)

    const jwe = await new FlattenedEncrypt(new TextEncoder().encode(content))
      .setProtectedHeader({
        alg: KeypairAlgorithm.Encrypting,
        enc: 'A256GCM',
      })
      .encrypt(key)

    return JSON.stringify(jwe)
  }

  /**
   * Decrypt a serialized JWE object with a serialized key
   * @param privateKey - Serialized private key
   * @param serializedJwe - JSON stringified JWE object (encrypted data)
   */
  public async decryptWithPrivateKey(serializedJwe: string, privateKey: string): Promise<string> {
    const key = await this.importPrivateKey(privateKey, KeypairAlgorithm.Encrypting)

    const jwe = JSON.parse(serializedJwe) as FlattenedJWE
    const decrypted = await flattenedDecrypt(jwe, key)

    return new TextDecoder().decode(decrypted.plaintext)
  }

  public async generateKeyPair(algo: KeypairAlgorithm): Promise<KeyPair> {
    const res = await generateKeyPair(algo, { extractable: true })

    const ret: KeyPair = {
      publicKey: await exportSPKI(res.publicKey),
      privateKey: await exportPKCS8(res.privateKey),
      gcmInitVector: ulid(),
    }

    return ret
  }

  public async generateSymmetricKey(): Promise<string> {
    const params: AesKeyGenParams = {
      name: 'AES-GCM',
      length: 256,
    }

    const key = await window.crypto.subtle.generateKey(params, true, ['encrypt', 'decrypt'])
    const exported = await window.crypto.subtle.exportKey('jwk', key)
    return exported.k
  }

  /**
   * @param - password being used to unwrap text
   * @param base64Text - The previously wrapped text to unwrap
   * @param initVector - The same init vector (random string) used to wrap the text
   * @param salt - The same salt used to wrap the text
   */
  public async encryptTextWithPassword(
    password: string,
    text: string,
    initVector: string,
    salt: string,
  ) {
    const key = await this.getPBKDF2KeyFromPassword(password, salt)

    const params2: AesGcmParams = {
      name: 'AES-GCM',
      iv: Buffer.from(initVector),
    }

    const encrypted = await window.crypto.subtle.encrypt(params2, key, Buffer.from(text))

    return Buffer.from(encrypted).toString('base64')
  }

  /**
   * @param - password being used to unwrap text
   * @param base64Text - The previously wrapped text to unwrap
   * @param initVector - The same init vector (random string) used to wrap the text
   * @param salt - The same salt used to wrap the text
   */
  public async decryptTextWithPassword(
    password: string,
    base64Text: string,
    initVector: string,
    salt: string,
  ): Promise<string> {
    const buffer = Buffer.from(base64Text, 'base64')
    const key = await this.getPBKDF2KeyFromPassword(password, salt)

    const params2: AesGcmParams = {
      name: 'AES-GCM',
      iv: Buffer.from(initVector),
    }

    const res = await window.crypto.subtle.decrypt(params2, key, buffer)
    return Buffer.from(res).toString('utf-8')
  }

  /**
   * Encrypt a string with a symmetric key
   */
  public async encryptWithSymmetricKey(key: string, data: string, iv: string) {
    const imported = await this.importSymmetricKey(key)
    return await this.encryptWithSymmetricKeyRaw(imported, data, iv)
  }

  public async decryptWithSymmetricKey(key: string, base64EncData: string, iv: string) {
    const imported = await this.importSymmetricKey(key)
    return await this.decryptWithSymmetricKeyRaw(imported, base64EncData, iv)
  }

  /**
   * Takes an object, creates a copy, encrypts user-specified fields in-place, and returns the same object.
   *
   * @param obj - The object that has the string fields to encrypt
   * @param symmetricKey - The serialized symmetric key to use for encryption
   * @param fieldsToEncrypt - The specific fields to encrypt
   * @param initVector - The init vector used to encrypt the fields
   * @param recursivelyEncryptObjects - If true, will recursively encrypt sub-objects
   * @param currentlyBelowTopLevel - Used internally to track if we're currently below the top level for recursive calls.  If below the top level, we'll encrypt all fields, because we're already inside an object that was specified to be encrypted.
   */
  public async encryptSpecifiedFields<T>(
    obj: T,
    symmetricKey: string,
    initVector: string,
    fieldsToEncrypt: string[],
    recursivelyEncryptObjects = true,
    currentlyBelowTopLevel = false,
  ): Promise<T> {
    // We need to make a deep copy of the object so we don't mutate the original
    obj = JSON.parse(JSON.stringify(obj))

    if (!symmetricKey) throw new Error('symmetricKey is required to call encryptSpecifiedFields')
    if (!initVector) throw new Error('initVector is required to call encryptSpecifiedFields')

    const symKey = await this.importSymmetricKey(symmetricKey)

    const fieldsToProcess = currentlyBelowTopLevel ? Object.keys(obj) : fieldsToEncrypt

    for (const field of fieldsToProcess) {
      if (!obj[field] && !currentlyBelowTopLevel) continue

      if (typeof obj[field] === 'object' && recursivelyEncryptObjects) {
        obj[field] = await this.encryptSpecifiedFields(
          obj[field],
          symmetricKey,
          initVector,
          fieldsToEncrypt,
          recursivelyEncryptObjects,
          true,
        )
      } else if (typeof obj[field] === 'string') {
        obj[field] = await this.encryptWithSymmetricKeyRaw(symKey, obj[field], initVector)
      }
    }
    return obj
  }

  /**
   * Takes an object with encrypted fields, creates a copy, decrypts the specified fields, and returns the new object
   *
   * @param obj - The object that has the string fields to decrypt
   * @param fieldsToDecrypt - The specific fields to encrypt
   * @param symmetricKey - The serialized symmetric key to use for decryption
   * @param initVector - The init vector used to encrypt the fields
   * @param recursivelyDecryptObjects - If true, will recursively decrypt sub-objects
   */
  public async decryptSpecifiedFields<T>(
    obj: T,
    symmetricKey: string,
    initVector: string,
    fieldsToDecrypt: string[],
    recursivelyDecryptObjects = true,
    currentlyBelowTopLevel = false,
  ): Promise<T> {
    // We need to make a deep copy of the object so we don't mutate the original
    obj = JSON.parse(JSON.stringify(obj))

    if (!symmetricKey) throw new Error('symmetricKey is required to call decryptSpecifiedFields')
    if (!initVector) throw new Error('initVector is required to call decryptSpecifiedFields')

    const symKey = await this.importSymmetricKey(symmetricKey)

    const fieldsToProcess = currentlyBelowTopLevel ? Object.keys(obj) : fieldsToDecrypt

    for (const field of fieldsToProcess) {
      if (!obj[field]) continue // Don't try to decrypt falsy fields

      try {
        if (typeof obj[field] === 'object' && recursivelyDecryptObjects) {
          obj[field] = await this.decryptSpecifiedFields(
            obj[field],
            symmetricKey,
            initVector,
            fieldsToDecrypt,
            recursivelyDecryptObjects,
            true,
          )
        } else if (typeof obj[field] === 'string') {
          obj[field] = await this.decryptWithSymmetricKeyRaw(symKey, obj[field], initVector)
        }
      } catch (err) {
        console.warn('Error decrypting field. Continuing to other fields.', field, err.message)
      }
    }
    return obj
  }

  /**
   * ****************** Getters and Setters ********************
   */

  public setPrivateEncryptionKey(privateKey: string) {
    this.keyStore.set(KeyIndexes.private_encryption_key, privateKey)
  }

  public getPrivateEncryptionKey(): string | null {
    return this.keyStore.get(KeyIndexes.private_encryption_key)
  }

  public setPrivateSigningKey(privateKey: string) {
    this.keyStore.set(KeyIndexes.private_signing_key, privateKey)
  }

  public getPrivateSigningKey(): string | null {
    return this.keyStore.get(KeyIndexes.private_signing_key)
  }

  public setPublicEncryptionKey(publicKey: string) {
    this.keyStore.set(KeyIndexes.public_encryption_key, publicKey)
  }
  public setPublicSigningKey(publicKey: string) {
    this.keyStore.set(KeyIndexes.public_signing_key, publicKey)
  }

  public getPublicEncryptionKey(): string | null {
    return this.keyStore.get(KeyIndexes.public_encryption_key)
  }

  public getPublicSigningKey(): string | null {
    return this.keyStore.get(KeyIndexes.public_signing_key)
  }

  /**
   * ********************** Private functions ************************
   */

  private async importPubKey(pubKeyString: string, algo: KeypairAlgorithm): Promise<KeyLike> {
    return await importSPKI(pubKeyString, algo)
  }

  private async importPrivateKey(privKeyString: string, algo: KeypairAlgorithm): Promise<KeyLike> {
    return importPKCS8(privKeyString, algo)
  }

  private async importSymmetricKey(key: string): Promise<CryptoKey> {
    const keyData: JsonWebKey = {
      key_ops: ['encrypt', 'decrypt'],
      ext: false,
      kty: 'oct',
      k: key,
      alg: 'A256GCM',
    }

    const res = await window.crypto.subtle.importKey('jwk', keyData, 'AES-GCM', false, [
      'encrypt',
      'decrypt',
    ])

    return res
  }

  private async getPBKDF2KeyFromPassword(password: string, salt: string) {
    const enc = new TextEncoder()
    const keyMaterial = await window.crypto.subtle.importKey(
      'raw',
      enc.encode(password),
      'PBKDF2',
      false,
      ['deriveBits', 'deriveKey'],
    )

    const saltBuffer = Buffer.from(salt)

    const params: Pbkdf2Params = {
      name: 'PBKDF2',
      salt: saltBuffer,
      iterations: 100000,
      hash: 'SHA-256',
    }

    const aesParams: AesKeyGenParams = {
      name: 'AES-GCM',
      length: 256,
    }

    return await window.crypto.subtle.deriveKey(params, keyMaterial, aesParams, true, [
      'encrypt',
      'decrypt',
    ])
  }

  private async signTextWithPrivateKeyRaw(
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

  private async verifySignatureRaw(
    signature: string,
    protectedStr: string,
    pubkey: KeyLike,
    content: string,
  ) {
    const payloadHash = await this.getSha256hash(content)
    const buff = Buffer.from(payloadHash, 'utf-8')
    const base64 = buff.toString('base64').replaceAll('=', '')

    const res = await flattenedVerify(
      { payload: base64, signature: signature, protected: protectedStr },
      pubkey,
    )

    return res
  }

  private async encryptWithSymmetricKeyRaw(
    key: CryptoKey,
    data: string,
    iv: string,
  ): Promise<string> {
    const res = await window.crypto.subtle.encrypt(
      { name: 'AES-GCM', iv: Buffer.from(iv) },
      key,
      new TextEncoder().encode(data),
    )

    return this.arrayBufferTob64(res)
  }

  /**
   * Decrypt a string with a symmetric key
   * @param base64EncData - encrypted data, base64 encoded
   */
  private async decryptWithSymmetricKeyRaw(key: CryptoKey, base64EncData: string, iv: string) {
    const res = await window.crypto.subtle.decrypt(
      { name: 'AES-GCM', iv: Buffer.from(iv) },
      key,
      this.b64ToArrayBuffer(base64EncData),
    )

    return this.arrayBufferToUtf8(res)
  }

  /**
   * ************** Utils *****************
   */

  private async arrayBufferTob64(buff: ArrayBuffer) {
    return Buffer.from(buff).toString('base64')
  }

  private b64ToArrayBuffer(input: string) {
    return Buffer.from(input, 'base64')
  }

  private async arrayBufferToUtf8(buff: ArrayBuffer) {
    return Buffer.from(buff).toString('utf-8')
  }

  private async getSha256hash(input: string) {
    return createHash('sha256').update(input).digest('base64')
  }
}

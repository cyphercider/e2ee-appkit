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
   * Takes an object and encrypts user-specified fields before returning the object.
   *
   * @param obj - The object that has the string fields to encrypt
   * @param fields - The specific fields to encrypt
   */
  public async encryptSpecifiedFields(
    obj: any,
    symKeySerialized: string,
    initVector: string,
    fields: string[],
  ) {
    const symKey = await this.importSymmetricKey(symKeySerialized)
    for (const field of fields) {
      obj[field] = await this.encryptWithSymmetricKeyRaw(symKey, obj[field], initVector)
    }
    return obj
  }

  /**
   * Takes an object with encrypted fields and decrypts the specified fields before turning the object.
   *
   * @param obj - The object that has the string fields to decrypt
   * @param fields - The specific fields to encrypt
   */
  public async decryptSpecifiedFields(
    obj: any,
    symKeyRaw: string,
    initVector: string,
    fields: string[],
  ) {
    const symKey = await this.importSymmetricKey(symKeyRaw)
    for (const field of fields) {
      obj[field] = await this.decryptWithSymmetricKeyRaw(symKey, obj[field], initVector)
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
      payload: res.payload,
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

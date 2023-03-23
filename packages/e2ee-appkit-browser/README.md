# E2EE-Appkit-Browser

The browser side of a kit for end-to-end-encrypted (e2ee) apps in Typescript.  Server side utilities for authentication are provided by [@cyphercider/e2ee-appkit-node](https://www.npmjs.com/package/@cyphercider/e2ee-appkit-node).

# Installation

npm i -S @cyphercider/e2ee-appkit-browser

# Overall Design

This libary makes it easy to:

- Generate keys (asymmetric signing, asymmetric encrypting, and symmetric ecrypting)
- Wrap text (including serialized keys) with a password.
- Encrypt, decrypt, and sign content
- Manage key storage in the browser using, powered by [Session Keystore](https://www.npmjs.com/package/session-keystore)
- User signup and login functions, calling backend APIs for obtaining and submitting signing challenges
- Session token (jwt) storage and decoding functionality

# Usage

## Crypto Service Initialization

```ts
import { CryptoService } from './crypto.service'

const cryptoService = new CryptoService()
```

## Asymmetric keypair generation, signing, and verification

Asymmetric signing and verification with RS256.

### Generate an asymmetric signing keypair

```ts
const keypair = await cryptoService.generateKeyPair(KeypairAlgorithm.Signing)
```

### Sign text with a private key

```ts
const signed = await cryptoService.signContent('text to sign', keypair.privateKey)
```

### Verify signature with a public key

```ts
// This function will throw an exception if the signature is invalid
await cryptoService.verifySignature(
  signed.signature,
  signed.protected,
  keypair.publicKey,
  challengeText,
)
```

## Asymmetric keypair generation, encryption, and decryption

Asymmetric encryption and decryption with RSA-OAEP-256.

### Generate a asymmetric encrypting keypair

```ts
const keypair = await cryptoService.generateKeyPair(KeypairAlgorithm.Encrypting)
```

### Encrypt content with a public key 

```ts
const encryptedContent = await cryptoService.encryptWithPublicKey(
  challengeContent,
  userKey.publicKey,
)
```

### Decrypt content with a private key

```ts
const decrypted = await cryptoService.decryptWithPrivateKey(encryptedJwe, userKey.privateKey)
```

## Symmetric key generation, encryption, and decryptiton

Symmetric encryption and decryption with AES-GCM (length 256).

### Generate a symmetric key

```ts
const key = await cryptoService.generateSymmetricKey()
const initVector = 'random string' // A non-secret random string required in symmetric encryption with AES-GCM 
const secret = 'thesecret'

```

### Encrypt with symmetric key

```ts
const encrypted = await cryptoService.encryptWithSymmetricKey(key, secret, initVector)
```

### Decrypt with symmetric key

```ts
const decrypted = await cryptoService.decryptWithSymmetricKey(key, encrypted, initVector)
```

## Encryption with key derived from a password

### Encrypt text with a password


```ts
const encryptedText = await cryptoService.encryptTextWithPassword(
  'the password',
  'text to encrypt',
  'An initialization vector', // This is a random string and must be the same for wrap / unwrap operations.  
  'salt', // A string used as a salt for PKBDF2.  You could use a user's username for this.
)
```

### Decrypt text with a password

```ts
const decryptedText = await cryptoService.decryptTextWithPassword(
  'the password',
  encryptedText,
  'An initialization vector', // This is a random string and must be the same for wrap / unwrap operations.  
  'salt', // A string used as a salt for PKBDF2.  You could use a user's username for this.
)
```

## Key storage via `session-keystore`

### Set user keys

```ts
cryptoService.setPublicEncryptionKey(pubEncrypting)
cryptoService.setPrivateEncryptionKey(privEncrypting)
cryptoService.setPublicSigningKey(pubSigning)
cryptoService.setPrivateSigningKey(privSigning)
```

### Get user keys

```ts
const pubEncr = cryptoService.getPublicEncryptionKey()
const privEncr = cryptoService.getPrivateEncryptionKey()
const pubSign = cryptoService.getPublicSigningKey()
const privSign = cryptoService.getPrivateSigningKey()
```

### Clear user keys

```ts
cryptoService.clearEncryptionKeys()
```

### Determine if all keys are present

```ts
const allArePresent = cryptoService.allKeysArePresent
```

## Algorithms used

These are the encryption algorithmns used by this library:

* Asymmetric signing - RS256
* Asymmetric encryption - RSA-OAEP-256
* Symmetric encryption - AES-GCM (length 256)
* Key derivation from password - PBKDF2
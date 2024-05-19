# E2EE-Appkit-Browser

The browser side of a kit for end-to-end-encrypted (e2ee) apps in Typescript.  Server side utilities for authentication are provided by [@cyphercider/e2ee-appkit-node](https://www.npmjs.com/package/@cyphercider/e2ee-appkit-node).

# Installation

```sh
npm i -S @cyphercider/e2ee-{appkit-browser,appkit-shared-models}
```

# Overall Design

This libary makes it easy to:

- Generate keys (asymmetric signing, asymmetric encrypting, and symmetric ecrypting)
- Wrap text (including serialized keys) with a password.
- Encrypt, decrypt, and sign content
- Manage key storage in the browser using, powered by [Session Keystore](https://www.npmjs.com/package/session-keystore)
- User signup and login functions, calling backend APIs for obtaining and submitting signing challenges
- Session token (jwt) storage and decoding functionality

# Crypto Service Usage

## Crypto Service Initialization

```ts
import { CryptoService } from './crypto.service'

const cryptoService = new CryptoService()
```

## Asymmetric keypair generation, signing, and verification

```ts
// Generate an asymmetric signing keypair
const keypair = await cryptoService.generateKeyPair(KeypairAlgorithm.Signing)

// Sign text with a private key
const signed = await cryptoService.signContent('text to sign', keypair.privateKey)

// Verify signature with a public key.  This function will throw an exception if the signature is invalid
await cryptoService.verifySignature(
  signed.signature,
  signed.protected,
  keypair.publicKey,
  challengeText,
)
```

## Asymmetric keypair generation, encryption, and decryption


```ts
// Generate a asymmetric encrypting keypair
const keypair = await cryptoService.generateKeyPair(KeypairAlgorithm.Encrypting)

// Encrypt content with a public key 
const encryptedContent = await cryptoService.encryptWithPublicKey(
  challengeContent,
  userKey.publicKey,
)

// Decrypt content with a private key
const decrypted = await cryptoService.decryptWithPrivateKey(encryptedJwe, userKey.privateKey)
```

## Symmetric key generation, encryption, and decryptiton

```ts
// Generate a symmetric key
const key = await cryptoService.generateSymmetricKey()
const initVector = 'random string' // A non-secret random string required in symmetric encryption with AES-GCM 
const secret = 'thesecret'


// Encrypt with symmetric key
const encrypted = await cryptoService.encryptWithSymmetricKey(key, secret, initVector)

// Decrypt with symmetric key
const decrypted = await cryptoService.decryptWithSymmetricKey(key, encrypted, initVector)
```

## Encryption with key derived from a password

```ts
// The init vector is a non-secret string and must be the same for wrap / unwrap operations.  
const INIT_VECTOR = 'same for encrypt and decrypt' 

// Encrypt text with a password
const encryptedText = await cryptoService.encryptTextWithPassword(
  'the password',
  'text to encrypt',
  INIT_VECTOR, 
  'salt', // A string used as a salt for PKBDF2.  You could use a user's username for this.
)

// Decrypt text with a password
const decryptedText = await cryptoService.decryptTextWithPassword(
  'the password',
  encryptedText,
  INIT_VECTOR, // This is a random string and must be the same for wrap / unwrap operations.
  'salt', // A string used as a salt for PKBDF2.  You could use a user's username for this.
)
```

## Key storage via `session-keystore`

The param optionalHoursUntilExpiry is the number of hours until the key expires.  The default setting is 24 hours.

```ts
// Set user keys
cryptoService.setPublicEncryptionKey(pubEncrypting, optionalHoursUntilExpiry)
cryptoService.setPrivateEncryptionKey(privEncrypting, optionalHoursUntilExpiry)
cryptoService.setPublicSigningKey(pubSigning, optionalHoursUntilExpiry)
cryptoService.setPrivateSigningKey(privSigning, optionalHoursUntilExpiry)

// Get user keys
const pubEncr = cryptoService.getPublicEncryptionKey()
const privEncr = cryptoService.getPrivateEncryptionKey()
const pubSign = cryptoService.getPublicSigningKey()
const privSign = cryptoService.getPrivateSigningKey()

// Clear user keys
cryptoService.clearEncryptionKeys()

// Determine if all keys are present
const allArePresent = cryptoService.allKeysArePresent
```

## User Service Usage

### Initialization

```ts
import {
  ConfigService,
  CryptoService,
  CryptoVerificationService,
  UserAuthenticationService,
} from '@cyphercider/e2ee-appkit-browser'

const cryptoService = new CryptoService()
/**
 *  ConfigService Initialization
 * 
 *  See additional (optional) params for AuthN routes for ConfigService initialization. Defaults are:
 * 
 *  challengeSubmitRoute = '/authn/submit-challenge',
 *  challengeRetrieveRoute = '/authn/get-challenge',
 *  loginSubmitRoute = '/login',
 *  signupRoute = '/authn/signup',
 *  loginFrontendRoute = '/login',
 */
const config = new ConfigService('http://your-backend-base-url') 
const verificationService = new CryptoVerificationService(cryptoService)
const userAuthService = new UserAuthenticationService(
  config,
  cryptoService,
  verificationService,
)
```

### Log in and log out

```ts
// Log in with a given username and password
await userAuthService.login(username, password)

// Log out. Clears session token and all user keys from the browser.
await userAuthService.logout()
```

### Get current session information

```ts
// Get current user.  Returns the decoded JWT contents following the most recent user login.  Contains at least the attribute `sub: string`
userAuthService.currentUser

// Get session token.  Returns token in local storage `session_token`.
const token = userAuthService.getSessionToken()

// Get refresh token. Returns token in local storage `refresh_token`.  You can manage the refresh token in your app.
const refreshToken = userAuthService.getRefreshToken()

// Get session token payload.  Gets token from storage, decodes, and returns.
const payload = userAuthService.getSessionTokenPayload()

// A boolean of whether the user is logged in.  Returns true if session token is in local storage and all keys are present in `session_keystore`.
const isLoggedIn = userAuthService.isLoggedIn
```

### Signup user

```ts
// Optional extra attributes you want to store about this user at signup time that will get passed in the payload to the login endpoint.
const extraAttributes = {
  attributeIWantInUserDetail: 'attribute value'
  ...
}

/**
 * Will attempt to create a user on the server and log in.  If successful, it will will return an object containing user keys and the user session token.  
 * 
 * The signup process will set the session token as well as `currentUser` if successful.
 * 
 * @username - Username for the user.  Will be used along with password to wrap the user's keys.
 * @password - Password for the user.  Will be used along with username to wrap the user's keys.
 * @extraAttributes - Optional extra attributes that will be included in the generated token
 * @signingKeypair - Optional signing keypair. Useful if you need to use a known keypair at the time of signup.
 * @encryptingKeypair - Optional signing keypair. Useful if you need to use a known keypair at the time of signup.
 * 
 */
await userAuthService.signupUser(username, password, extraAttributes?, encryptingKeypair?, signingKeypair?)
const user = userAuthService.currentUser // Get cached / decoded token with user information (including any additional token attributes added by your server logic)
```

### Login user

Similar to signup, but without the extra attributes.

```ts
await userAuthService.login(username, password)
const user = userAuthService.currentUser // Get cached / decoded token with user information (including any additional token attributes added by your server logic)
```

### Log out user

```ts
userAuthService.logout()
```

### Redirect user to frontend login page

```ts
userAuthService.redirectToLogin()
```


## Algorithms used

These are the encryption algorithmns used by this library:

* Asymmetric signing - RS256
* Asymmetric encryption - RSA-OAEP-256
* Symmetric encryption - AES-GCM (length 256)
* Key derivation from password - PBKDF2

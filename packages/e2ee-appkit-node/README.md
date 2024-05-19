# E2ee-appkit-node

A small node.js library, written in Typescript, that provides authentication components that are complimentary with [@cyphercider/e2ee-appkit-browser](https://www.npmjs.com/package/@cyphercider/e2ee-appkit-browser).

# Overall Design

This library runs in node and provides:

* Signature verification using a user signing public key
* Challenge generation (for user login)
* Challenge response verification and user token (JWT) generation if verification is successful

# Installation

```sh
npm i -S @cyphercider/e2ee-{appkit-node,appkit-shared-models}
```

# Usage

## Import CryptoKit

CryptoKit is a stateless class with static methods, and so requires no initialization.

```ts
import { CryptoKit } from '@cyphercider/e2ee-appkit-node'
```

## Get challenge example function

This requires you plug in your own persistence to retrieve the user from your database.

```ts
import { ChallengeResponseInterface, UserInterface, CryptoKit } from '@cyphercider/e2ee-appkit-shared-models'

async function getChallenge(login: LoginRequestResource): Promise<ChallengeResponseInterface> {
  const user = // ... your function to retrieve the user definition from storage.  Must implement UserInterface

  if (!user) {
    throw new NotFoundException(`Could not find user ${login.username}`)
  }

  const challenge = CryptoKit.getChallenge(user)

  return { ...challenge, ...any other attributes you need to return }
}
```

## Submit challenge example function

```ts

import { ChallengeResponseInterface, UserInterface, CryptoKit } from '@cyphercider/e2ee-appkit-shared-models'

async function submitChallengeWrapped(submit: SubmitChallengeInterface): Promise<string> {
  // Bring your own persistence to retrieve the user, implementing UserInterface
  const user = await usersService.getUser(submit.username)

  const payload = await CryptoKit.submitChallenge(
    submit,
    user,
    {
      username: user.id,
      tokenattr2: value,
      tokenattr3: value,
      ...
    }, // Optional. default {}
    5, // Optional.  Max age of challenge.  Beyond this, the user will need a new challenge to sign.
    BadRequestException as any, // Optional. If you want to bring your own exception
    ForbiddenException as any, // Optional. If you want to bring your own exception
  )

  // replace this with your own jwt signing service or library
  const token = jwtService.sign(payload)
  const refreshToken = jwtService.sign(payload, { expiresIn: '30d' })
  return { token, refreshToken }
}
```

## Verify a signature

You can verify a signature manually using the `verifySignature` function.

```ts
try {
  await this.verifySignature(
    '[serialized signature]',
    '["protected" string created during signing]',
    '[public signing key]',
    '[original string that was signed]',
  )
} catch (err) {
  // Handle the case that verification fails.
}
```
## Algorithms used

These are the encryption algorithmns used by this library:

* Asymmetric signing and verification - RS256








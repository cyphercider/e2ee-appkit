import { KeypairAlgorithm, SubmitChallengeInterface } from '@cyphercider/e2ee-appkit-shared-models'
import { TestUtils } from './crypto-test.service'
import { CryptoKit } from './cryptokit.service'
import { NumberUtils, TimeUtils } from '../utils'

describe('node authentication service', () => {
  afterEach(() => {
    jest.clearAllMocks()
  })

  it('should verify signature', async () => {
    const keypair = await TestUtils.generateKeyPair(KeypairAlgorithm.Signing)

    const signature = await TestUtils.signContent('content', keypair.privateKey)

    expect(signature).toBeTruthy()

    // should run and not throw
    await CryptoKit.verifySignature(
      signature.signature,
      signature.protected,
      keypair.publicKey,
      'content',
    )
  })

  it('should get a challenge', async () => {
    const user = await TestUtils.generateTestUser()

    const challenge = CryptoKit.getChallenge(user)
    const split = challenge.challengeText.split('-')

    if (!NumberUtils.isNumber(split[1])) {
      throw new Error(`Second half of challenge text, ${split[1]}, must be a numeric timestamp!`)
    }

    const ts = NumberUtils.toNumber(split[1])
    const minutesDiff = TimeUtils.minutesBeforeNow(ts)
    if (minutesDiff > 10) {
      throw new Error(`Challenge is too old (${minutesDiff} minutes).  Please retry login.`)
    }
  })

  it('should submit a challenge', async () => {
    const user = await TestUtils.generateTestUser()

    const challenge = CryptoKit.getChallenge(user)

    const signed = await TestUtils.signContent(
      challenge.challengeText,
      user.encryptedPrivateSigningKey,
    )

    const submit: SubmitChallengeInterface = {
      username: user.username,
      protected: signed.protected,
      challengeText: challenge.challengeText,
      signature: signed.signature,
    }

    const res = await CryptoKit.submitChallenge(submit, user, { additional: 'attr' })
    expect(res.sub).toEqual(user.username)
    expect(res.additional).toEqual('attr')
  })

  it('should throw exception if challenge second segment is not a number', async () => {
    const user = await TestUtils.generateTestUser()

    const challenge = CryptoKit.getChallenge(user)

    // set to invalid challenge
    challenge.challengeText = 'invalid-challenge'

    const signed = await TestUtils.signContent(
      challenge.challengeText,
      user.encryptedPrivateSigningKey,
    )

    const submit: SubmitChallengeInterface = {
      username: user.username,
      protected: signed.protected,
      challengeText: challenge.challengeText,
      signature: signed.signature,
    }

    expect(async () => {
      await CryptoKit.submitChallenge(submit, user, { additional: 'attr' })
    }).rejects.toThrow()
  })

  it('should throw exception if challenge doesnt have two segments separated by a -', async () => {
    const user = await TestUtils.generateTestUser()

    const challenge = CryptoKit.getChallenge(user)

    // set to invalid challenge
    challenge.challengeText = 'invalid'

    const signed = await TestUtils.signContent(
      challenge.challengeText,
      user.encryptedPrivateSigningKey,
    )

    const submit: SubmitChallengeInterface = {
      username: user.username,
      protected: signed.protected,
      challengeText: challenge.challengeText,
      signature: signed.signature,
    }

    expect(async () => {
      await CryptoKit.submitChallenge(submit, user, { additional: 'attr' })
    }).rejects.toThrow()
  })

  it('should throw exception if challenge is too old', async () => {
    const user = await TestUtils.generateTestUser()

    const challenge = CryptoKit.getChallenge(user)

    // set to invalid challenge
    challenge.challengeText = 'invalid-0'

    const signed = await TestUtils.signContent(
      challenge.challengeText,
      user.encryptedPrivateSigningKey,
    )

    const submit: SubmitChallengeInterface = {
      username: user.username,
      protected: signed.protected,
      challengeText: challenge.challengeText,
      signature: signed.signature,
    }

    expect(async () => {
      await CryptoKit.submitChallenge(submit, user, { additional: 'attr' })
    }).rejects.toThrow()
  })

  it('should throw exception if signature is invalid', async () => {
    const user = await TestUtils.generateTestUser()

    const challenge = CryptoKit.getChallenge(user)

    const signed = await TestUtils.signContent(
      challenge.challengeText,
      user.encryptedPrivateSigningKey,
    )

    const submit: SubmitChallengeInterface = {
      username: user.username,
      protected: signed.protected,
      challengeText: challenge.challengeText,
      signature: 'bad signature',
    }

    expect(async () => {
      await CryptoKit.submitChallenge(submit, user, { additional: 'attr' })
    }).rejects.toThrow()
  })
})

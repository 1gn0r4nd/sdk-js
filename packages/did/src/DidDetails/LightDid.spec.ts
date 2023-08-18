/**
 * Copyright (c) 2018-2023, BOTLabs GmbH.
 *
 * This source code is licensed under the BSD 4-Clause "Original" license
 * found in the LICENSE file in the root directory of this source tree.
 */

import { DidDocument, DidUrl } from '@kiltprotocol/types'
import { Crypto } from '@kiltprotocol/utils'

import * as Did from '../index.js'

/*
 * Functions tested:
 * - createLightDidDocument
 * - parseDocumentFromLightDid
 *
 * Functions tested in integration tests:
 * - getKeysForExtrinsic
 * - authorizeExtrinsic
 */

describe('When creating an instance from the details', () => {
  it('correctly assign the right sr25519 authentication key, x25519 encryption key, and service endpoints', () => {
    const authKey = Crypto.makeKeypairFromSeed(undefined, 'sr25519')
    const encKey = Crypto.makeEncryptionKeypairFromSeed(
      new Uint8Array(32).fill(1)
    )
    const service: Did.NewService[] = [
      {
        id: `#service-1`,
        type: ['type-1'],
        serviceEndpoint: ['x:url-1'],
      },
      {
        id: '#service-2',
        type: ['type-21', 'type-22'],
        serviceEndpoint: ['x:url-21', 'x:url-22'],
      },
    ]

    const lightDid = Did.createLightDidDocument({
      authentication: [authKey],
      keyAgreement: [encKey],
      service,
    })

    expect(lightDid).toEqual(<DidDocument>{
      id: `did:kilt:light:00${authKey.address}:z17GNCdxLqMYTMC5pnnDrPZGxLEFcXvDamtGNXeNkfSaFf8cktX6erFJiQy8S3ugL981NNys7Rz8DJiaNPZi98v1oeFVL7PjUGNTz1g3jgZo4VgQri2SYHBifZFX9foHZH4DreZXFN66k5dPrvAtBpFXaiG2WZkkxsnxNWxYpqWPPcxvbTE6pJbXxWKjRUd7rog1h9vjA93QA9jMDxm6BSGJHACFgSPUU3UTLk2kjNwT2bjZVvihVFu1zibxwHjowb7N6UQfieJ7ny9HnaQy64qJvGqh4NNtpwkhwm5DTYUoAeAhjt3a6TWyxmBgbFdZF7`,
      verificationMethod: [
        {
          id: `did:kilt:light:00${authKey.address}:z17GNCdxLqMYTMC5pnnDrPZGxLEFcXvDamtGNXeNkfSaFf8cktX6erFJiQy8S3ugL981NNys7Rz8DJiaNPZi98v1oeFVL7PjUGNTz1g3jgZo4VgQri2SYHBifZFX9foHZH4DreZXFN66k5dPrvAtBpFXaiG2WZkkxsnxNWxYpqWPPcxvbTE6pJbXxWKjRUd7rog1h9vjA93QA9jMDxm6BSGJHACFgSPUU3UTLk2kjNwT2bjZVvihVFu1zibxwHjowb7N6UQfieJ7ny9HnaQy64qJvGqh4NNtpwkhwm5DTYUoAeAhjt3a6TWyxmBgbFdZF7#authentication`,
          controller: `did:kilt:light:00${authKey.address}:z17GNCdxLqMYTMC5pnnDrPZGxLEFcXvDamtGNXeNkfSaFf8cktX6erFJiQy8S3ugL981NNys7Rz8DJiaNPZi98v1oeFVL7PjUGNTz1g3jgZo4VgQri2SYHBifZFX9foHZH4DreZXFN66k5dPrvAtBpFXaiG2WZkkxsnxNWxYpqWPPcxvbTE6pJbXxWKjRUd7rog1h9vjA93QA9jMDxm6BSGJHACFgSPUU3UTLk2kjNwT2bjZVvihVFu1zibxwHjowb7N6UQfieJ7ny9HnaQy64qJvGqh4NNtpwkhwm5DTYUoAeAhjt3a6TWyxmBgbFdZF7`,
          publicKeyMultibase: 'aaa',
          type: 'Sr25519VerificationKey2020',
        },
        {
          id: `did:kilt:light:00${authKey.address}:z17GNCdxLqMYTMC5pnnDrPZGxLEFcXvDamtGNXeNkfSaFf8cktX6erFJiQy8S3ugL981NNys7Rz8DJiaNPZi98v1oeFVL7PjUGNTz1g3jgZo4VgQri2SYHBifZFX9foHZH4DreZXFN66k5dPrvAtBpFXaiG2WZkkxsnxNWxYpqWPPcxvbTE6pJbXxWKjRUd7rog1h9vjA93QA9jMDxm6BSGJHACFgSPUU3UTLk2kjNwT2bjZVvihVFu1zibxwHjowb7N6UQfieJ7ny9HnaQy64qJvGqh4NNtpwkhwm5DTYUoAeAhjt3a6TWyxmBgbFdZF7#encryption`,
          controller: `did:kilt:light:00${authKey.address}:z17GNCdxLqMYTMC5pnnDrPZGxLEFcXvDamtGNXeNkfSaFf8cktX6erFJiQy8S3ugL981NNys7Rz8DJiaNPZi98v1oeFVL7PjUGNTz1g3jgZo4VgQri2SYHBifZFX9foHZH4DreZXFN66k5dPrvAtBpFXaiG2WZkkxsnxNWxYpqWPPcxvbTE6pJbXxWKjRUd7rog1h9vjA93QA9jMDxm6BSGJHACFgSPUU3UTLk2kjNwT2bjZVvihVFu1zibxwHjowb7N6UQfieJ7ny9HnaQy64qJvGqh4NNtpwkhwm5DTYUoAeAhjt3a6TWyxmBgbFdZF7`,
          publicKeyMultibase: 'aaa',
          type: 'X25519KeyAgreementKey2019',
        },
      ],
      authentication: ['#authentication'],
      keyAgreement: ['#encryption'],
      service: [
        {
          id: `did:kilt:light:00${authKey.address}:z17GNCdxLqMYTMC5pnnDrPZGxLEFcXvDamtGNXeNkfSaFf8cktX6erFJiQy8S3ugL981NNys7Rz8DJiaNPZi98v1oeFVL7PjUGNTz1g3jgZo4VgQri2SYHBifZFX9foHZH4DreZXFN66k5dPrvAtBpFXaiG2WZkkxsnxNWxYpqWPPcxvbTE6pJbXxWKjRUd7rog1h9vjA93QA9jMDxm6BSGJHACFgSPUU3UTLk2kjNwT2bjZVvihVFu1zibxwHjowb7N6UQfieJ7ny9HnaQy64qJvGqh4NNtpwkhwm5DTYUoAeAhjt3a6TWyxmBgbFdZF7#service-1`,
          type: ['type-1'],
          serviceEndpoint: ['x:url-1'],
        },
        {
          id: `did:kilt:light:00${authKey.address}:z17GNCdxLqMYTMC5pnnDrPZGxLEFcXvDamtGNXeNkfSaFf8cktX6erFJiQy8S3ugL981NNys7Rz8DJiaNPZi98v1oeFVL7PjUGNTz1g3jgZo4VgQri2SYHBifZFX9foHZH4DreZXFN66k5dPrvAtBpFXaiG2WZkkxsnxNWxYpqWPPcxvbTE6pJbXxWKjRUd7rog1h9vjA93QA9jMDxm6BSGJHACFgSPUU3UTLk2kjNwT2bjZVvihVFu1zibxwHjowb7N6UQfieJ7ny9HnaQy64qJvGqh4NNtpwkhwm5DTYUoAeAhjt3a6TWyxmBgbFdZF7#service-2`,
          type: ['type-21', 'type-22'],
          serviceEndpoint: ['x:url-21', 'x:url-22'],
        },
      ],
    })
  })

  it('correctly assign the right ed25519 authentication key and encryption key', () => {
    const authKey = Crypto.makeKeypairFromSeed()
    const encKey = Crypto.makeEncryptionKeypairFromSeed(
      new Uint8Array(32).fill(1)
    )

    const lightDid = Did.createLightDidDocument({
      authentication: [authKey],
      keyAgreement: [encKey],
    })

    expect(Did.parse(lightDid.id).address).toStrictEqual(authKey.address)

    expect(lightDid).toEqual(<DidDocument>{
      id: `did:kilt:light:01${authKey.address}:z15dZSRuzEPTFnBErPxqJie4CmmQH1gYKSQYxmwW5Qhgz5Sr7EYJA3J65KoC5YbgF3NGoBsTY2v6zwj1uDnZzgXzLy8R72Fhjmp8ujY81y2AJc8uQ6s2pVbAMZ6bnvaZ3GVe8bMjY5MiKFySS27qRi`,
      verificationMethod: [
        {
          id: `did:kilt:light:01${authKey.address}:z15dZSRuzEPTFnBErPxqJie4CmmQH1gYKSQYxmwW5Qhgz5Sr7EYJA3J65KoC5YbgF3NGoBsTY2v6zwj1uDnZzgXzLy8R72Fhjmp8ujY81y2AJc8uQ6s2pVbAMZ6bnvaZ3GVe8bMjY5MiKFySS27qRi#authentication`,
          controller: `did:kilt:light:01${authKey.address}:z15dZSRuzEPTFnBErPxqJie4CmmQH1gYKSQYxmwW5Qhgz5Sr7EYJA3J65KoC5YbgF3NGoBsTY2v6zwj1uDnZzgXzLy8R72Fhjmp8ujY81y2AJc8uQ6s2pVbAMZ6bnvaZ3GVe8bMjY5MiKFySS27qRi`,
          publicKeyMultibase: 'aaa',
          type: 'Ed25519VerificationKey2018',
        },
        {
          id: `did:kilt:light:01${authKey.address}:z15dZSRuzEPTFnBErPxqJie4CmmQH1gYKSQYxmwW5Qhgz5Sr7EYJA3J65KoC5YbgF3NGoBsTY2v6zwj1uDnZzgXzLy8R72Fhjmp8ujY81y2AJc8uQ6s2pVbAMZ6bnvaZ3GVe8bMjY5MiKFySS27qRi#encryption`,
          controller: `did:kilt:light:01${authKey.address}:z15dZSRuzEPTFnBErPxqJie4CmmQH1gYKSQYxmwW5Qhgz5Sr7EYJA3J65KoC5YbgF3NGoBsTY2v6zwj1uDnZzgXzLy8R72Fhjmp8ujY81y2AJc8uQ6s2pVbAMZ6bnvaZ3GVe8bMjY5MiKFySS27qRi`,
          publicKeyMultibase: 'aaa',
          type: 'X25519KeyAgreementKey2019',
        },
      ],
      authentication: ['#authentication'],
      keyAgreement: ['#encryption'],
    })
  })

  it('throws for unsupported authentication key type', () => {
    const authKey = Crypto.makeKeypairFromSeed(undefined, 'ecdsa')
    const invalidInput = {
      // Not an authentication key type
      authentication: [authKey],
    }
    expect(() =>
      Did.createLightDidDocument(
        invalidInput as unknown as Did.CreateDocumentInput
      )
    ).toThrowError()
  })

  it('throws for unsupported encryption key type', () => {
    const authKey = Crypto.makeKeypairFromSeed()
    const encKey = Crypto.makeEncryptionKeypairFromSeed()
    const invalidInput = {
      authentication: [authKey],
      // Not an encryption key type
      keyAgreement: [{ publicKey: encKey.publicKey, type: 'bls' }],
    }
    expect(() =>
      Did.createLightDidDocument(
        invalidInput as unknown as Did.CreateDocumentInput
      )
    ).toThrowError()
  })
})

describe('When creating an instance from a URI', () => {
  it('correctly assign the right authentication key, encryption key, and service endpoints', () => {
    const authKey = Crypto.makeKeypairFromSeed(undefined, 'sr25519')
    const encKey = Crypto.makeEncryptionKeypairFromSeed(
      new Uint8Array(32).fill(1)
    )
    const endpoints: Did.NewService[] = [
      {
        id: '#service-1',
        type: ['type-1'],
        serviceEndpoint: ['x:url-1'],
      },
      {
        id: '#service-2',
        type: ['type-21', 'type-22'],
        serviceEndpoint: ['x:url-21', 'x:url-22'],
      },
    ]
    // We are sure this is correct because of the described case above
    const expectedLightDid = Did.createLightDidDocument({
      authentication: [authKey],
      keyAgreement: [encKey],
      service: endpoints,
    })

    const { address } = Did.parse(expectedLightDid.id)
    const builtLightDid = Did.parseDocumentFromLightDid(expectedLightDid.id)

    expect(builtLightDid).toStrictEqual(expectedLightDid)
    expect(builtLightDid).toStrictEqual(<DidDocument>{
      id: `did:kilt:light:00${address}:z17GNCdxLqMYTMC5pnnDrPZGxLEFcXvDamtGNXeNkfSaFf8cktX6erFJiQy8S3ugL981NNys7Rz8DJiaNPZi98v1oeFVL7PjUGNTz1g3jgZo4VgQri2SYHBifZFX9foHZH4DreZXFN66k5dPrvAtBpFXaiG2WZkkxsnxNWxYpqWPPcxvbTE6pJbXxWKjRUd7rog1h9vjA93QA9jMDxm6BSGJHACFgSPUU3UTLk2kjNwT2bjZVvihVFu1zibxwHjowb7N6UQfieJ7ny9HnaQy64qJvGqh4NNtpwkhwm5DTYUoAeAhjt3a6TWyxmBgbFdZF7`,
      verificationMethod: [
        {
          id: `did:kilt:light:00${address}:z17GNCdxLqMYTMC5pnnDrPZGxLEFcXvDamtGNXeNkfSaFf8cktX6erFJiQy8S3ugL981NNys7Rz8DJiaNPZi98v1oeFVL7PjUGNTz1g3jgZo4VgQri2SYHBifZFX9foHZH4DreZXFN66k5dPrvAtBpFXaiG2WZkkxsnxNWxYpqWPPcxvbTE6pJbXxWKjRUd7rog1h9vjA93QA9jMDxm6BSGJHACFgSPUU3UTLk2kjNwT2bjZVvihVFu1zibxwHjowb7N6UQfieJ7ny9HnaQy64qJvGqh4NNtpwkhwm5DTYUoAeAhjt3a6TWyxmBgbFdZF7#authentication`,
          controller: `did:kilt:light:00${address}:z17GNCdxLqMYTMC5pnnDrPZGxLEFcXvDamtGNXeNkfSaFf8cktX6erFJiQy8S3ugL981NNys7Rz8DJiaNPZi98v1oeFVL7PjUGNTz1g3jgZo4VgQri2SYHBifZFX9foHZH4DreZXFN66k5dPrvAtBpFXaiG2WZkkxsnxNWxYpqWPPcxvbTE6pJbXxWKjRUd7rog1h9vjA93QA9jMDxm6BSGJHACFgSPUU3UTLk2kjNwT2bjZVvihVFu1zibxwHjowb7N6UQfieJ7ny9HnaQy64qJvGqh4NNtpwkhwm5DTYUoAeAhjt3a6TWyxmBgbFdZF7`,
          publicKeyMultibase: 'aaa',
          type: 'Sr25519VerificationKey2020',
        },
        {
          id: `did:kilt:light:00${address}:z17GNCdxLqMYTMC5pnnDrPZGxLEFcXvDamtGNXeNkfSaFf8cktX6erFJiQy8S3ugL981NNys7Rz8DJiaNPZi98v1oeFVL7PjUGNTz1g3jgZo4VgQri2SYHBifZFX9foHZH4DreZXFN66k5dPrvAtBpFXaiG2WZkkxsnxNWxYpqWPPcxvbTE6pJbXxWKjRUd7rog1h9vjA93QA9jMDxm6BSGJHACFgSPUU3UTLk2kjNwT2bjZVvihVFu1zibxwHjowb7N6UQfieJ7ny9HnaQy64qJvGqh4NNtpwkhwm5DTYUoAeAhjt3a6TWyxmBgbFdZF7#encryption`,
          controller: `did:kilt:light:00${address}:z17GNCdxLqMYTMC5pnnDrPZGxLEFcXvDamtGNXeNkfSaFf8cktX6erFJiQy8S3ugL981NNys7Rz8DJiaNPZi98v1oeFVL7PjUGNTz1g3jgZo4VgQri2SYHBifZFX9foHZH4DreZXFN66k5dPrvAtBpFXaiG2WZkkxsnxNWxYpqWPPcxvbTE6pJbXxWKjRUd7rog1h9vjA93QA9jMDxm6BSGJHACFgSPUU3UTLk2kjNwT2bjZVvihVFu1zibxwHjowb7N6UQfieJ7ny9HnaQy64qJvGqh4NNtpwkhwm5DTYUoAeAhjt3a6TWyxmBgbFdZF7`,
          publicKeyMultibase: 'aaa',
          type: 'X25519KeyAgreementKey2019',
        },
      ],
      authentication: ['#authentication'],
      keyAgreement: ['#encryption'],
      service: [
        {
          id: `did:kilt:light:00${address}:z17GNCdxLqMYTMC5pnnDrPZGxLEFcXvDamtGNXeNkfSaFf8cktX6erFJiQy8S3ugL981NNys7Rz8DJiaNPZi98v1oeFVL7PjUGNTz1g3jgZo4VgQri2SYHBifZFX9foHZH4DreZXFN66k5dPrvAtBpFXaiG2WZkkxsnxNWxYpqWPPcxvbTE6pJbXxWKjRUd7rog1h9vjA93QA9jMDxm6BSGJHACFgSPUU3UTLk2kjNwT2bjZVvihVFu1zibxwHjowb7N6UQfieJ7ny9HnaQy64qJvGqh4NNtpwkhwm5DTYUoAeAhjt3a6TWyxmBgbFdZF7#service-1`,
          type: ['type-1'],
          serviceEndpoint: ['x:url-1'],
        },
        {
          id: `did:kilt:light:00${address}:z17GNCdxLqMYTMC5pnnDrPZGxLEFcXvDamtGNXeNkfSaFf8cktX6erFJiQy8S3ugL981NNys7Rz8DJiaNPZi98v1oeFVL7PjUGNTz1g3jgZo4VgQri2SYHBifZFX9foHZH4DreZXFN66k5dPrvAtBpFXaiG2WZkkxsnxNWxYpqWPPcxvbTE6pJbXxWKjRUd7rog1h9vjA93QA9jMDxm6BSGJHACFgSPUU3UTLk2kjNwT2bjZVvihVFu1zibxwHjowb7N6UQfieJ7ny9HnaQy64qJvGqh4NNtpwkhwm5DTYUoAeAhjt3a6TWyxmBgbFdZF7#service-2`,
          type: ['type-21', 'type-22'],
          serviceEndpoint: ['x:url-21', 'x:url-22'],
        },
      ],
    })
  })

  it('fail if a fragment is present according to the options', () => {
    const authKey = Crypto.makeKeypairFromSeed()
    const encKey = Crypto.makeEncryptionKeypairFromSeed()
    const service: Did.NewService[] = [
      {
        id: '#service-1',
        type: ['type-1'],
        serviceEndpoint: ['x:url-1'],
      },
      {
        id: '#service-2',
        type: ['type-21', 'type-22'],
        serviceEndpoint: ['x:url-21', 'x:url-22'],
      },
    ]

    // We are sure this is correct because of the described case above
    const expectedLightDid = Did.createLightDidDocument({
      authentication: [authKey],
      keyAgreement: [encKey],
      service,
    })

    const uriWithFragment: DidUrl = `${expectedLightDid.id}#authentication`

    expect(() => Did.parseDocumentFromLightDid(uriWithFragment, true)).toThrow()
    expect(() =>
      Did.parseDocumentFromLightDid(uriWithFragment, false)
    ).not.toThrow()
  })

  it('fail if the URI is not correct', () => {
    const validKiltAddress = Crypto.makeKeypairFromSeed()
    const incorrectURIs = [
      'did:kilt:light:sdasdsadas',
      // @ts-ignore not a valid DID uri
      'random-uri',
      'did:kilt:light',
      'did:kilt:light:',
      // Wrong auth key encoding
      `did:kilt:light:11${validKiltAddress}`,
      // Full DID
      `did:kilt:${validKiltAddress}`,
      // Random encoded details
      `did:kilt:light:00${validKiltAddress}:randomdetails`,
    ]
    incorrectURIs.forEach((uri) => {
      expect(() => Did.parseDocumentFromLightDid(uri as DidUrl)).toThrow()
    })
  })
})

/**
 * Copyright (c) 2018-2023, BOTLabs GmbH.
 *
 * This source code is licensed under the BSD 4-Clause "Original" license
 * found in the LICENSE file in the root directory of this source tree.
 */

/// <reference lib="dom" />

import type { KiltCredentialV1 as KiltCredential } from '@kiltprotocol/core'
import type { Identity } from '@kiltprotocol/sdk-js'
import type {
  KiltEncryptionKeypair,
  KiltKeyringPair,
} from '@kiltprotocol/types'

const { kilt } = window

const {
  ConfigService,
  CType,
  Did,
  Blockchain,
  Utils: { Crypto, ss58Format, Signers },
  KiltCredentialV1,
  Presentation,
  issuer,
  verifier,
  holder,
  makeIdentity,
} = kilt

ConfigService.set({ submitTxResolveOn: Blockchain.IS_IN_BLOCK })

function makeEncryptionKeypair(seed: string): KiltEncryptionKeypair {
  const { secretKey, publicKey } = Crypto.naclBoxPairFromSecret(
    Crypto.hash(seed, 256)
  )
  return {
    secretKey,
    publicKey,
    type: 'x25519',
  }
}

async function createFullDidIdentity(
  payer: KiltKeyringPair,
  seed: string,
  keyType: KiltKeyringPair['type'] = 'sr25519'
): Promise<Identity> {
  const keypair = Crypto.makeKeypairFromUri(seed, keyType)

  const encryptionKey = makeEncryptionKeypair(seed)

  const signers = await kilt.Utils.Signers.getSignersForKeypair({
    keypair,
    id: keypair.address,
  })

  const storeTx = await Did.getStoreTx(
    {
      authentication: [keypair],
      assertionMethod: [keypair],
      capabilityDelegation: [keypair],
      keyAgreement: [encryptionKey],
    },
    payer.address,
    signers
  )
  await Blockchain.signAndSubmitTx(storeTx, payer)

  const identity = await makeIdentity({
    did: `did:kilt:${keypair.address}`,
    keypairs: [keypair],
  })
  return identity
}

async function runAll() {
  // init sdk kilt config and connect to chain
  const api = await kilt.connect('ws://127.0.0.1:9944')

  // Accounts
  console.log('Account setup started')
  const FaucetSeed =
    'receive clutch item involve chaos clutch furnace arrest claw isolate okay together'
  const payer = Crypto.makeKeypairFromUri(FaucetSeed)
  const payerSigners = await Signers.getSignersForKeypair({
    keypair: payer,
  })

  const alice = await createFullDidIdentity(payer, '//Alice')

  console.log('alice setup done')

  const bob = await createFullDidIdentity(payer, '//Bob')
  console.log('bob setup done')

  // Light DID Account creation workflow
  const authPublicKey = Crypto.coToUInt8(
    '0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa'
  )
  const encPublicKey = Crypto.coToUInt8(
    '0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb'
  )
  const address = Crypto.encodeAddress(authPublicKey, ss58Format)
  const testDid = Did.createLightDidDocument({
    authentication: [{ publicKey: authPublicKey, type: 'ed25519' }],
    keyAgreement: [{ publicKey: encPublicKey, type: 'x25519' }],
  })
  if (
    testDid.id !==
    `did:kilt:light:01${address}:z1Ac9CMtYCTRWjetJfJqJoV7FcPDD9nHPHDHry7t3KZmvYe1HQP1tgnBuoG3enuGaowpF8V88sCxytDPDy6ZxhW`
  ) {
    throw new Error('DID Test Unsuccessful')
  } else console.info(`light DID successfully created`)

  // Chain DID workflow -> creation & deletion
  console.log('DID workflow started')
  const keypair = Crypto.makeKeypairFromUri('//Foo', 'ed25519')

  const accountSigners = await kilt.Utils.Signers.getSignersForKeypair({
    keypair,
    id: keypair.address,
  })

  const didStoreTx = await Did.getStoreTx(
    { authentication: [keypair] },
    payer.address,
    accountSigners
  )
  await Blockchain.signAndSubmitTx(didStoreTx, payer)

  const identity = await makeIdentity({
    did: `did:kilt:${keypair.address}`,
    keypairs: [keypair],
  })

  const deleteTx = await Did.authorizeTx(
    identity.did,
    api.tx.did.delete(0n),
    identity.signers,
    payer.address
  )
  await Blockchain.signAndSubmitTx(deleteTx, payer)

  const resolvedAgain = await Did.resolve(identity.did)
  if (resolvedAgain.didDocumentMetadata.deactivated) {
    console.info('DID successfully deleted')
  } else {
    throw new Error('DID was not deleted')
  }

  // CType workflow
  console.log('CType workflow started')
  const DriversLicense = CType.fromProperties('Drivers License', {
    name: {
      type: 'string',
    },
    age: {
      type: 'integer',
    },
  })

  const cTypeStoreTx = await Did.authorizeTx(
    alice.did,
    api.tx.ctype.add(CType.toChain(DriversLicense)),
    alice.signers,
    payer.address
  )
  await Blockchain.signAndSubmitTx(cTypeStoreTx, payer)

  await CType.verifyStored(DriversLicense)
  console.info('CType successfully stored on chain')

  // Attestation workflow
  console.log('Attestation workflow started')
  const content = { name: 'Bob', age: 21 }

  const credential = await issuer.createCredential({
    cType: DriversLicense,
    claims: content,
    subject: bob.did,
    issuer: alice.did,
  })

  console.info('Credential subject conforms to CType')

  if (
    credential.credentialSubject.name !== content.name ||
    credential.credentialSubject.age !== content.age ||
    credential.credentialSubject.id !== bob.did
  ) {
    throw new Error('Claim content inside Credential mismatching')
  }

  // turn alice into a transaction submission enabled identity
  alice.submitterAccount = payer.address
  await alice.addSigner(...payerSigners)

  const issued = await issuer.issue(credential, alice as any)
  console.info('Credential issued')

  KiltCredentialV1.validateStructure(issued as KiltCredential.Interface)
  console.info('Credential structure validated')

  const credentialResult = await verifier.verifyCredential(
    issued,
    {},
    {
      ctypeLoader: [DriversLicense],
    }
  )
  if (credentialResult.verified) {
    console.info('Credential proof verified')
    console.info('Credential status verified')
  } else {
    throw new Error(`Credential failed to verify: ${credentialResult.error}`, {
      cause: credentialResult,
    })
  }

  const challenge = kilt.Utils.Crypto.hashStr(
    kilt.Utils.Crypto.mnemonicGenerate()
  )

  const derived = await holder.deriveProof(issued, {
    disclose: { allBut: ['/credentialSubject/name'] },
  })

  const presentation = await holder.createPresentation(
    [derived],
    bob,
    {},
    {
      challenge,
    }
  )
  console.info('Presentation created')

  Presentation.validateStructure(presentation)
  console.info('Presentation structure validated')

  const presentationResult = await verifier.verifyPresentation(presentation, {
    presentation: { challenge },
  })
  if (presentationResult.verified) {
    console.info('Presentation verified')
  } else {
    throw new Error(
      [
        'Presentation failed to verify',
        ...(presentationResult.error ?? []),
      ].join('\n  '),
      { cause: presentationResult }
    )
  }
}

window.runAll = runAll

/**
 * Copyright (c) 2018-2024, BOTLabs GmbH.
 *
 * This source code is licensed under the BSD 4-Clause "Original" license
 * found in the LICENSE file in the root directory of this source tree.
 */

import type { RegistryTypes } from '@polkadot/types/types'
import { mergeType } from './mergeType.js'
import { types18 } from './types_18.js'

export const types19: RegistryTypes = mergeType(
  // Use the old types as the base of the new types.
  types18,

  // We add these new type:
  {
    ServiceEndpoints: {
      contentHash: 'Hash',
      urls: 'Vec<Url>',
      contentType: 'ContentType',
    },
    DidFragmentUpdateAction_ServiceEndpoints: {
      _enum: {
        Ignore: 'Null',
        Change: 'ServiceEndpoints',
        Delete: 'Null',
      },
    },
    DidFragmentUpdateAction_DidVerificationKey: {
      _enum: {
        Ignore: 'Null',
        Change: 'DidVerificationKey',
        Delete: 'Null',
      },
    },
    ContentType: {
      _enum: ['ApplicationJson', 'ApplicationJsonLd'],
    },

    // Updated types
    DidCreationDetails: {
      did: 'DidIdentifierOf',
      newKeyAgreementKeys: 'BTreeSet<DidEncryptionKey>',
      newAttestationKey: 'Option<DidVerificationKey>',
      newDelegationKey: 'Option<DidVerificationKey>',
      newServiceEndpoints: 'Option<ServiceEndpoints>',
    },
    DidUpdateDetails: {
      newAuthenticationKey: 'Option<DidVerificationKey>',
      newKeyAgreementKeys: 'BTreeSet<DidEncryptionKey>',
      attestationKeyUpdate: 'DidFragmentUpdateAction_DidVerificationKey',
      delegationKeyUpdate: 'DidFragmentUpdateAction_DidVerificationKey',
      publicKeysToRemove: 'BTreeSet<KeyIdOf>',
      serviceEndpointsUpdate: 'DidFragmentUpdateAction_ServiceEndpoints',
    },
    DidDetails: {
      authenticationKey: 'KeyIdOf',
      keyAgreementKeys: 'BTreeSet<KeyIdOf>',
      delegationKey: 'Option<KeyIdOf>',
      attestationKey: 'Option<KeyIdOf>',
      publicKeys: 'BTreeMap<KeyIdOf, DidPublicKeyDetails>',
      serviceEndpoints: 'Option<ServiceEndpoints>',
      lastTxCounter: 'u64',
    },
    DidStorageVersion: {
      _enum: ['V1', 'V2'],
    },
  },

  // Remove old DID types:
  ['DidVerificationKeyUpdateAction']
)

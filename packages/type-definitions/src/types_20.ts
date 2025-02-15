/**
 * Copyright (c) 2018-2024, BOTLabs GmbH.
 *
 * This source code is licensed under the BSD 4-Clause "Original" license
 * found in the LICENSE file in the root directory of this source tree.
 */

import type { RegistryTypes } from '@polkadot/types/types'
import { mergeType } from './mergeType.js'
import { types19 } from './types_19.js'

export const types20: RegistryTypes = mergeType(
  // Use the old types as the base of the new types.
  types19,

  // We add these new type:
  {
    // Staking
    OrderedSet: 'BoundedVec<Stake, MaxCollatorCandidates>',
    MaxCollatorCandidates: 'u32',
    Collator: {
      id: 'AccountId',
      stake: 'Balance',
      // new
      delegators: 'OrderedSet<Stake, MaxDelegatorsPerCollator>',
      total: 'Balance',
      state: 'CollatorStatus',
    },
    MaxDelegatorsPerCollator: 'u32',
    Delegator: {
      // new
      delegations: 'OrderedSet<Stake, MaxCollatorsPerDelegator>',
      total: 'Balance',
    },
    MaxCollatorsPerDelegator: 'u32',
    StakingStorageVersion: {
      _enum: ['V1_0_0', 'V2_0_0', 'V3_0_0', 'V4'],
    },

    // Attestation
    MaxDelegatedAttestations: 'u32',

    // KILT Launch
    MaxClaims: 'u32',

    // Delegation
    DelegationNode: {
      hierarchyRootId: 'DelegationNodeIdOf',
      parent: 'Option<DelegationNodeIdOf>',
      // new
      children: 'BoundedBTreeSet<DelegationNodeIdOf, MaxChildren>',
      details: 'DelegationDetails',
    },
    MaxChildren: 'u32',

    // DIDs
    DidNewKeyAgreementKeys:
      'BoundedBTreeSet<DidEncryptionKey, MaxNewKeyAgreementKeys>',
    DidKeyAgreementKeys: 'BoundedBTreeSet<KeyIdOf, MaxTotalKeyAgreementKeys>',
    DidVerificationKeysToRevoke:
      'BoundedBTreeSet<KeyIdOf, MaxVerificationKeysToRevoke>',
    MaxNewKeyAgreementKeys: 'u32',
    MaxTotalKeyAgreementKeys: 'u32',
    MaxVerificationKeysToRevoke: 'u32',
    MaxPublicKeysPerDid: 'u32',
    DidPublicKeyMap:
      'BoundedBTreeMap<KeyIdOf, DidPublicKeyDetails, MaxPublicKeysPerDid>',
    DidCreationDetails: {
      did: 'DidIdentifierOf',
      newKeyAgreementKeys: 'DidNewKeyAgreementKeys',
      newAttestationKey: 'Option<DidVerificationKey>',
      newDelegationKey: 'Option<DidVerificationKey>',
      newServiceEndpoints: 'Option<ServiceEndpoints>',
    },
    DidUpdateDetails: {
      newAuthenticationKey: 'Option<DidVerificationKey>',
      // new
      newKeyAgreementKeys: 'DidNewKeyAgreementKeys',
      attestationKeyUpdate: 'DidFragmentUpdateAction_DidVerificationKey',
      delegationKeyUpdate: 'DidFragmentUpdateAction_DidVerificationKey',
      // new
      publicKeysToRemove: 'DidVerificationKeysToRevoke',
      serviceEndpointsUpdate: 'DidFragmentUpdateAction_ServiceEndpoints',
    },
    DidDetails: {
      authenticationKey: 'KeyIdOf',
      // new
      keyAgreementKeys: 'DidKeyAgreementKeys',
      delegationKey: 'Option<KeyIdOf>',
      attestationKey: 'Option<KeyIdOf>',
      // new
      publicKeys: 'DidPublicKeyMap',
      serviceEndpoints: 'Option<ServiceEndpoints>',
      lastTxCounter: 'u64',
    },
    ServiceEndpoints: {
      contentHash: 'Hash',
      // new
      urls: 'BoundedVec<Url, MaxEndpointUrlsCount>',
      contentType: 'ContentType',
    },
    MaxUrlLength: 'u32',
    MaxEndpointUrlsCount: 'u32',
    StorageError: {
      _enum: {
        DidAlreadyPresent: 'Null',
        DidNotPresent: 'Null',
        DidKeyNotPresent: 'DidVerificationKeyRelationship',
        VerificationKeyNotPresent: 'Null',
        CurrentlyActiveKey: 'Null',
        MaxTxCounterValue: 'Null',
        // new
        MaxPublicKeysPerDidKeyIdentifierExceeded: 'Null',
        MaxTotalKeyAgreementKeysExceeded: 'Null',
        MaxOldAttestationKeysExceeded: 'Null',
      },
    },
  },

  // Remove old DID types:
  ['CollatorSnapshot']
)

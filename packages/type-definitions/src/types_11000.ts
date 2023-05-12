/**
 * Copyright (c) 2018-2023, BOTLabs GmbH.
 *
 * This source code is licensed under the BSD 4-Clause "Original" license
 * found in the LICENSE file in the root directory of this source tree.
 */

import type { RegistryTypes } from '@polkadot/types/types'

import { types10900 } from './types_10900.js'

export const types11000: RegistryTypes = {
  ...types10900,
  // DipProvider state_call
  CompleteMerkleProof: {
    root: 'MerkleRoot',
    proof: 'MerkleProof',
  },
  MerkleRoot: 'Hash',
  MerkleProof: {
    blinded: 'BlindedLeaves',
    revealed: 'RevealedLeaves',
  },
  BlindedLeaves: 'Vec<BlindedValue>',
  BlindedValue: 'Bytes',
  RevealedLeaves: 'Vec<RevealedLeaf>',
  RevealedLeaf: {
    _enum: {
      KeyReference: '(KeyReferenceKey, KeyReferenceValue)',
      KeyDetails: '(KeyDetailsKey, KeyDetailsValue)',
    },
  },
  KeyReferenceKey: '(KeyId, KeyRelationship)',
  KeyReferenceValue: 'Null',
  KeyDetailsKey: 'KeyId',
  KeyDetailsValue: 'DidDidDetailsDidPublicKeyDetails',
  KeyId: 'Hash',
  KeyRelationship: {
    _enum: {
      Encryption: 'Null',
      Verification: 'VerificationRelationship',
    },
  },
  VerificationRelationship: {
    _enum: [
      'Authentication',
      'CapabilityDelegation',
      'CapabilityInvocation',
      'AssertionMethod',
    ],
  },
}

/**
 * Copyright (c) 2018-2022, BOTLabs GmbH.
 *
 * This source code is licensed under the BSD 4-Clause "Original" license
 * found in the LICENSE file in the root directory of this source tree.
 */

import type {
  IAttestation,
  IDelegationHierarchyDetails,
  ICredential,
  DidUri,
} from '@kiltprotocol/types'
import { DataUtils, SDKErrors } from '@kiltprotocol/utils'
import { Utils as DidUtils } from '@kiltprotocol/did'
import { DelegationNode } from '../delegation/DelegationNode.js'
import * as Credential from '../credential/index.js'

/**
 * An [[Attestation]] certifies a [[Claim]], sent by a claimer in the form of a [[Credential]]. [[Attestation]]s are **written on the blockchain** and are **revocable**.
 *
 * An [[Attestation]] can be queried from the chain. It's stored on-chain in a map:
 * * the key is the hash of the corresponding claim;
 * * the value is a tuple ([[CType]] hash, account, id of the Delegation, and revoked flag).
 *
 * @packageDocumentation
 */

/**
 * Checks whether the input meets all the required criteria of an [[IAttestation]] object.
 * Throws on invalid input.
 *
 * @param input The potentially only partial [[IAttestation]].
 */
export function verifyDataStructure(input: IAttestation): void {
  if (!input.cTypeHash) {
    throw new SDKErrors.CTypeHashMissingError()
  }
  DataUtils.verifyIsHex(input.cTypeHash, 256)

  if (!input.claimHash) {
    throw new SDKErrors.ClaimHashMissingError()
  }
  DataUtils.verifyIsHex(input.claimHash, 256)

  if (typeof input.delegationId !== 'string' && input.delegationId !== null) {
    throw new SDKErrors.DelegationIdTypeError()
  }

  if (!input.owner) {
    throw new SDKErrors.OwnerMissingError()
  }
  DidUtils.validateKiltDidUri(input.owner, 'Did')

  if (typeof input.revoked !== 'boolean') {
    throw new SDKErrors.RevokedTypeError()
  }
}

/**
 * Builds a new instance of an [[Attestation]], from a complete set of input required for an attestation.
 *
 * @param credential - The base credential for attestation.
 * @param attesterDid - The attester's DID, used to attest to the underlying claim.
 * @returns A new [[Attestation]] object.
 */
export function fromCredentialAndDid(
  credential: ICredential,
  attesterDid: DidUri
): IAttestation {
  const attestation = {
    claimHash: credential.rootHash,
    cTypeHash: credential.claim.cTypeHash,
    delegationId: credential.delegationId,
    owner: attesterDid,
    revoked: false,
  }
  verifyDataStructure(attestation)
  return attestation
}

/**
 * Tries to query the delegationId and if successful query the rootId.
 *
 * @param input - The ID of the Delegation stored in [[Attestation]] , or the whole Attestation object.
 * @returns A promise of either null if querying was not successful or the affiliated [[DelegationNode]].
 */
export async function getDelegationDetails(
  input: IAttestation['delegationId'] | IAttestation
): Promise<IDelegationHierarchyDetails | null> {
  if (input === null) {
    return null
  }

  let delegationId: IAttestation['delegationId']

  if (typeof input === 'string') {
    delegationId = input
  } else {
    delegationId = input.delegationId
  }

  if (!delegationId) {
    return null
  }

  const delegationNode = await DelegationNode.query(delegationId)
  if (!delegationNode) {
    return null
  }
  return delegationNode.getHierarchyDetails()
}

/**
 * Custom Type Guard to determine input being of type IAttestation.
 *
 * @param input The potentially only partial IAttestation.
 * @returns Boolean whether input is of type IAttestation.
 */
export function isIAttestation(input: unknown): input is IAttestation {
  try {
    verifyDataStructure(input as IAttestation)
  } catch (error) {
    return false
  }
  return true
}

/**
 * Verifies whether the data of the given attestation matches the one from the corresponding credential. It is valid if:
 * * the [[Credential]] object has valid data (see [[Credential.verifyDataIntegrity]]);
 * and
 * * the hash of the [[Credential]] object, and the hash of the [[Attestation]].
 *
 * @param attestation - The attestation to verify.
 * @param credential - The credential to verify against.
 */
export function verifyAgainstCredential(
  attestation: IAttestation,
  credential: ICredential
): void {
  if (
    credential.claim.cTypeHash !== attestation.cTypeHash ||
    credential.rootHash !== attestation.claimHash
  ) {
    throw new SDKErrors.CredentialUnverifiableError(
      'Attestation does not match credential'
    )
  }
  Credential.verifyDataIntegrity(credential)
}

/**
 * Copyright (c) 2018-2024, BOTLabs GmbH.
 *
 * This source code is licensed under the BSD 4-Clause "Original" license
 * found in the LICENSE file in the root directory of this source tree.
 */

import type { RegistryTypes } from '@polkadot/types/types'

import { types10720 } from './types_10720.js'

export const types10800: RegistryTypes = {
  ...types10720,

  // Public credentials state_call
  PublicCredentialFilter: {
    _enum: {
      ctypeHash: 'Hash',
      attester: 'AccountId32',
    },
  },
  PublicCredentialError: {
    _enum: ['InvalidSubjectId'],
  },

  // Staking get_staking_rates
  StakingRates: {
    collatorStakingRate: 'Perquintill',
    collatorRewardRate: 'Perquintill',
    delegatorStakingRate: 'Perquintill',
    delegatorRewardRate: 'Perquintill',
  },
}

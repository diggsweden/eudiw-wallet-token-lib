// SPDX-FileCopyrightText: 2024 Digg - Agency for Digital Government
//
// SPDX-License-Identifier: EUPL-1.2

package se.digg.wallet.datatypes.common;

import java.util.List;

/**
 * TokenValidator interface
 */
public interface TokenValidator {
  /**
   * Validates a token using an optional list of trusted keys. I no trusted keys are provided validation will be attempted
   * using a key provided in the token.
   * The key used to validate the token will be included in {@link TokenValidationResult} if present
   *
   * @param token The token to be validated as a byte array.
   * @param trustedKeys optional list of trusted keys used for validation.
   * @return An instance of TokenValidationResult containing information about the validation result.
   */
  TokenValidationResult validateToken(
    byte[] token,
    List<TrustedKey> trustedKeys
  ) throws TokenValidationException;
}

// SPDX-FileCopyrightText: 2025 Digg - Agency for Digital Government
//
// SPDX-License-Identifier: EUPL-1.2

package se.digg.wallet.datatypes.common;

import java.util.List;

/**
 * Defines an interface for validating verifiable presentations.
 * <p>
 * A verifiable presentation, which may include selective disclosures, can be validated using this interface.
 * Validation is performed using a combination of the presented token, a set of validation input parameters,
 * and a list of trusted signing keys.
 * <p>
 * Proving signing keys is optional. If keys are provided, validation verifies that a trusted key is used to sign the presentation.
 * If no trusted keys are provided, then the result lists the used signing key/path.
 * <p>
 * The process ensures the integrity and authenticity of the token, while also verifying its structural correctness,
 * optional expiration, and the presence of a valid nonce.
 * <p>
 * Methods in this interface may throw exceptions indicating issues with the token's integrity, parsing, or validation.
 */
public interface PresentationValidator {
  /**
   * Validates a verifiable presentation and ensures its integrity, authenticity, and adherence to the required structure.
   * The validation process involves verifying the structural correctness of the presentation, checking the expiration time,
   * ensuring the presence and validity of a nonce, and optionally validating it against a specified list of trusted keys.
   *
   * @param presentation the byte array representation of the verifiable presentation to be validated.
   * @param presentationValidationInput input parameters needed for the validation process, such as a request nonce.
   * @param trustedKeys an optional list of trusted keys used to verify the signing key of the presentation. If no trusted
   *                    keys are provided, the result will include details of the signing key/path used for validation.
   * @return an instance of {@code TokenValidationResult} containing validation details such as the validation key,
   *         issue time, expiration time, and nonce.
   * @throws TokenValidationException if the presentation validation fails due to structural or cryptographic errors.
   * @throws TokenParsingException if an error occurs during parsing of the presentation.
   */
  TokenValidationResult validatePresentation(
    byte[] presentation,
    PresentationValidationInput presentationValidationInput,
    List<TrustedKey> trustedKeys
  ) throws TokenValidationException, TokenParsingException;
}

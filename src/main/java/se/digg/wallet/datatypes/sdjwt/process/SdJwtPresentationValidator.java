// SPDX-FileCopyrightText: 2025 Digg - Agency for Digital Government
//
// SPDX-License-Identifier: EUPL-1.2

package se.digg.wallet.datatypes.sdjwt.process;

import com.nimbusds.jose.Payload;
import java.time.Duration;
import java.util.List;
import java.util.Map;
import lombok.extern.slf4j.Slf4j;
import se.digg.wallet.datatypes.common.PresentationValidationInput;
import se.digg.wallet.datatypes.common.PresentationValidator;
import se.digg.wallet.datatypes.common.TokenAttributeType;
import se.digg.wallet.datatypes.common.TokenValidationException;
import se.digg.wallet.datatypes.common.TrustedKey;
import se.digg.wallet.datatypes.sdjwt.data.SdJwt;
import se.digg.wallet.datatypes.sdjwt.data.SdJwtPresentationValidationInput;

/**
 * Implementation of the PresentationValidator interface for validating SD JWT (Selective Disclosure JSON Web Token) presentations.
 * This class performs validation on given SD JWT presentations, ensuring compliance with expected security and integrity constraints,
 * including checking the wallet key binding and validating the request nonce.
 * <p>
 * This validator supports optional configuration for handling time skew during validation through the timeSkew parameter.
 * If no configuration is provided, a default time skew of 30 seconds is applied.
 * <p>
 * Validation involves verifying the integrity of the SD JWT, ensuring appropriate key binding protection, and checking that
 * the nonce provided by the presentation aligns with the expected request nonce.
 */
@Slf4j
public class SdJwtPresentationValidator implements PresentationValidator {

  private final Duration timeSkew;

  /**
   * Default constructor for the SdKwtPresentationValidator class.
   *
   * Initializes the instance with a default time skew value of 30 seconds. This time skew is used during the
   * validation process to account for minor time discrepancies between systems, ensuring robust handling of
   * time-dependent SD JWT validation constraints.
   *
   * The SdKwtPresentationValidator class is used to validate SD JWT presentations, ensuring their
   * integrity, security, and compliance with wallet key binding requirements and the expected request nonce.
   */
  public SdJwtPresentationValidator() {
    this.timeSkew = Duration.ofSeconds(30);
  }

  /**
   * Constructs an SdKwtPresentationValidator with a specified time skew.
   * The time skew is used to handle potential minor discrepancies in system clocks during validation processes.
   *
   * @param timeSkew the allowed time deviation between systems for validation purposes. Must not be null.
   */
  public SdJwtPresentationValidator(final Duration timeSkew) {
    this.timeSkew = timeSkew;
  }

  /**
   * Validates an SD JWT presentation by ensuring proper key binding and conformity to the expected input values.
   * <p>
   * If No trusted keys are provided, any key will be allowed as signing key. If this option is used,
   * the verifier must validate through other means that the signing key provided in the result used to sign is trusted.
   *
   * @param presentation the byte array representation of the SD JWT presentation to be validated
   * @param presentationValidationInput the validation input containing required parameters such as request nonce
   * @param trustedKeys an optional list of trusted keys used to verify the presentation's integrity
   * @return A {@code TokenValidationResult} containing the result of the validation process, including status and additional data.
   * @throws TokenValidationException If the validation fails due to invalid or missing values, or key binding issues.
   */
  @Override
  public SdJwtTokenValidationResult validatePresentation(
    byte[] presentation,
    PresentationValidationInput presentationValidationInput,
    List<TrustedKey> trustedKeys
  ) throws TokenValidationException {
    if (log.isTraceEnabled()) {
      log.trace(
        "Validating SD JWT presentation:\n{}",
        new String(presentation)
      );
    } else {
      log.debug("Validating SD WT presentation");
    }

    // Check input type
    if (
      !(presentationValidationInput instanceof
        SdJwtPresentationValidationInput input)
    ) {
      throw new TokenValidationException(
        "Presentation validation input of SD JWT presentations must be of type " +
        "SdJwtPresentationValidationInput"
      );
    }

    try {
      SdJwtTokenValidator tokenValidator = new SdJwtTokenValidator(timeSkew);
      SdJwtTokenValidationResult sdJwtTokenValidationResult =
        tokenValidator.validateToken(presentation, trustedKeys);
      if (!sdJwtTokenValidationResult.isKeyBindingProtection()) {
        throw new TokenValidationException(
          "Wallet key binding is missing or invalid"
        );
      }
      String keyBindingNonce =
        sdJwtTokenValidationResult.getPresentationRequestNonce();
      if (
        keyBindingNonce == null ||
        !keyBindingNonce.equals(input.getRequestNonce())
      ) {
        throw new TokenValidationException("Key binding nonce invalid");
      }
      if (
        !sdJwtTokenValidationResult.getAudience().contains(input.getAudience())
      ) {
        throw new TokenValidationException(
          "Token is not issued for the intended audience"
        );
      }

      Map<TokenAttributeType, Object> disclosedAttributes =
        getDisclosedAttributes(
          sdJwtTokenValidationResult.getDisclosedTokenPayload()
        );
      sdJwtTokenValidationResult.setDisclosedAttributes(disclosedAttributes);

      return sdJwtTokenValidationResult;
    } catch (TokenValidationException e) {
      throw e;
    } catch (Exception e) {
      throw new TokenValidationException(
        "Failed to validate SD JWT presentation",
        e
      );
    }
  }

  private Map<TokenAttributeType, Object> getDisclosedAttributes(
    Payload disclosedTokenPayload
  ) {
    Map<TokenAttributeType, Object> disclosedAttributes =
      new java.util.HashMap<>();
    if (disclosedTokenPayload == null) {
      return disclosedAttributes;
    }
    disclosedTokenPayload
      .toJSONObject()
      .entrySet()
      .stream()
      .filter(entry -> !SdJwt.STD_CLAIMS.contains(entry.getKey()))
      .filter(entry -> !"_sd".equals(entry.getKey()))
      .forEach(
        entry ->
          disclosedAttributes.put(
            new TokenAttributeType(entry.getKey()),
            entry.getValue()
          )
      );
    return disclosedAttributes;
  }
}

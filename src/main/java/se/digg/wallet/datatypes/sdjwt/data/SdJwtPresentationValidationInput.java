// SPDX-FileCopyrightText: 2025 diggsweden/eudiw-wallet-token-lib
//
// SPDX-License-Identifier: EUPL-1.2

package se.digg.wallet.datatypes.sdjwt.data;

import lombok.Data;
import lombok.EqualsAndHashCode;
import se.digg.wallet.datatypes.common.PresentationValidationInput;

/**
 * Represents the input required for validating a presentation in the SD-JWT context. Extends the
 * functionality of PresentationValidationInput to include additional properties specific to SD-JWT
 * validation.
 */
@EqualsAndHashCode(callSuper = true)
@Data
public class SdJwtPresentationValidationInput
    extends PresentationValidationInput {

  /**
   * Constructs an instance of SdJwtPresentationValidationInput, initializing the input required for
   * validating an SD-JWT presentation with the provided request nonce and audience.
   *
   * @param requestNonce the unique identifier provided by the relying party, used to verify the
   *        request's authenticity and prevent replay attacks.
   * @param audience the intended recipient or audience for the SD-JWT, used to validate that the
   *        token is presented to the correct party.
   */
  public SdJwtPresentationValidationInput(
      String requestNonce,
      String audience) {
    super(requestNonce);
    this.audience = audience;
  }

  /** The intended recipient or audience for the SD-JWT */
  private String audience;

  /**
   * Creates and returns a new builder instance for constructing an SdJwtPresentationValidationInput
   * object.
   *
   * @return an SdJwtPresentationValidationInputBuilder for step-by-step construction of
   *         SdJwtPresentationValidationInput objects.
   */
  public static SdJwtPresentationValidationInputBuilder builder() {
    return new SdJwtPresentationValidationInputBuilder();
  }

  /**
   * A builder class for constructing instances of SdJwtPresentationValidationInput. This builder
   * provides a step-by-step approach to set properties required for SD-JWT presentation validation.
   */
  public static class SdJwtPresentationValidationInputBuilder {
    /** The object being built */
    SdJwtPresentationValidationInput input;

    /**
     * Initializes a new instance of the SdJwtPresentationValidationInputBuilder class. This builder
     * facilitates the creation and configuration of SdJwtPresentationValidationInput instances for
     * SD-JWT presentation validation.
     */
    public SdJwtPresentationValidationInputBuilder() {
      input = new SdJwtPresentationValidationInput(null, null);
    }

    /**
     * Sets the request nonce on the underlying SdJwtPresentationValidationInput being built. The
     * nonce is used to ensure request uniqueness and prevent replay attacks.
     *
     * @param requestNonce the request nonce to be set
     * @return the current instance of SdJwtPresentationValidationInputBuilder for method chaining
     */
    public SdJwtPresentationValidationInputBuilder requestNonce(String requestNonce) {
      input.setRequestNonce(requestNonce);
      return this;
    }

    /**
     * Sets the audience for the underlying SdJwtPresentationValidationInput being built. The
     * audience typically represents the intended recipient(s) or verifier(s) of the SD-JWT
     * presentation, ensuring it is targeted to the correct party.
     *
     * @param audience the audience identifier to be set
     * @return the current instance of SdJwtPresentationValidationInputBuilder for method chaining
     */
    public SdJwtPresentationValidationInputBuilder audience(String audience) {
      input.setAudience(audience);
      return this;
    }

    /**
     * Constructs and returns the final instance of SdJwtPresentationValidationInput using the
     * parameters set in the builder.
     *
     * @return the configured SdJwtPresentationValidationInput object
     */
    public SdJwtPresentationValidationInput build() {
      return input;
    }

  }
}

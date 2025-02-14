// SPDX-FileCopyrightText: 2025 Digg - Agency for Digital Government
//
// SPDX-License-Identifier: EUPL-1.2

package se.digg.wallet.datatypes.sdjwt.data;

import lombok.Data;
import lombok.EqualsAndHashCode;
import se.digg.wallet.datatypes.common.PresentationValidationInput;

/**
 * Represents the input required for validating a presentation in the SD-JWT context.
 * Extends the functionality of PresentationValidationInput to include additional
 * properties specific to SD-JWT validation.
 */
@EqualsAndHashCode(callSuper = true)
@Data
public class SdJwtPresentationValidationInput
  extends PresentationValidationInput {

  /**
   * Constructs an instance of SdJwtPresentationValidationInput, initializing the input
   * required for validating an SD-JWT presentation with the provided request nonce and audience.
   *
   * @param requestNonce the unique identifier provided by the relying party, used to
   *                     verify the request's authenticity and prevent replay attacks.
   * @param audience     the intended recipient or audience for the SD-JWT, used to
   *                     validate that the token is presented to the correct party.
   */
  public SdJwtPresentationValidationInput(
    String requestNonce,
    String audience
  ) {
    super(requestNonce);
    this.audience = audience;
  }

  /** The intended recipient or audience for the SD-JWT */
  private String audience;
}

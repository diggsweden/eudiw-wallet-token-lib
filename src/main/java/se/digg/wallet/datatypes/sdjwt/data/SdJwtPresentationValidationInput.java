// SPDX-FileCopyrightText: 2025 Digg - Agency for Digital Government
//
// SPDX-License-Identifier: EUPL-1.2

package se.digg.wallet.datatypes.sdjwt.data;

import lombok.Data;
import lombok.EqualsAndHashCode;
import se.digg.wallet.datatypes.common.PresentationValidationInput;

@EqualsAndHashCode(callSuper = true)
@Data
public class SdJwtPresentationValidationInput
  extends PresentationValidationInput {

  public SdJwtPresentationValidationInput(
    String requestNonce,
    String audience
  ) {
    super(requestNonce);
    this.audience = audience;
  }

  private String audience;
}

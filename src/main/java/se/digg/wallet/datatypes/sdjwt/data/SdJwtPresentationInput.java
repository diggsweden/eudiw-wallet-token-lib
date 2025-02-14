// SPDX-FileCopyrightText: 2025 Digg - Agency for Digital Government
//
// SPDX-License-Identifier: EUPL-1.2

package se.digg.wallet.datatypes.sdjwt.data;

import java.util.List;
import lombok.Data;
import lombok.EqualsAndHashCode;
import se.digg.wallet.datatypes.common.PresentationInput;
import se.digg.wallet.datatypes.common.TokenSigningAlgorithm;

@EqualsAndHashCode(callSuper = true)
@Data
public class SdJwtPresentationInput extends PresentationInput<List<String>> {

  private String audience;

  public static SdJwtPresentationInputbuilder builder() {
    return new SdJwtPresentationInputbuilder();
  }

  public static class SdJwtPresentationInputbuilder {

    private final SdJwtPresentationInput presentationInput;

    public SdJwtPresentationInputbuilder() {
      presentationInput = new SdJwtPresentationInput();
    }

    public SdJwtPresentationInputbuilder token(byte[] token) {
      presentationInput.token = token;
      return this;
    }

    public SdJwtPresentationInputbuilder nonce(String nonce) {
      presentationInput.nonce = nonce;
      return this;
    }

    public SdJwtPresentationInputbuilder algorithm(
      TokenSigningAlgorithm algorithm
    ) {
      presentationInput.algorithm = algorithm;
      return this;
    }

    public SdJwtPresentationInputbuilder disclosures(List<String> disclosures) {
      presentationInput.disclosures = disclosures;
      return this;
    }

    public SdJwtPresentationInputbuilder audience(String audience) {
      presentationInput.audience = audience;
      return this;
    }

    public SdJwtPresentationInput build() {
      return presentationInput;
    }
  }
}

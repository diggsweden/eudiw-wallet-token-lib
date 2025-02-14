// SPDX-FileCopyrightText: 2025 Digg - Agency for Digital Government
//
// SPDX-License-Identifier: EUPL-1.2

package se.digg.wallet.datatypes.sdjwt.data;

import java.util.List;
import lombok.Data;
import lombok.EqualsAndHashCode;
import se.digg.wallet.datatypes.common.PresentationInput;
import se.digg.wallet.datatypes.common.TokenSigningAlgorithm;

/**
 * A specialized implementation of the {@link PresentationInput} class designed to handle
 * specific requirements for SD-JWT presentations. This class includes additional fields and methods
 * tailored to SD-JWT workflows, such as specifying an audience and associated disclosures.
 */
@EqualsAndHashCode(callSuper = true)
@Data
public class SdJwtPresentationInput extends PresentationInput<List<String>> {

  /** The audience of the SD JWT */
  private String audience;

  /**
   * Creates and returns a new builder instance of {@code SdJwtPresentationInputbuilder}, which
   * facilitates the construction of {@code SdJwtPresentationInput} objects by allowing chained
   * method calls to set various properties.
   *
   * @return a new instance of {@code SdJwtPresentationInputbuilder}
   */
  public static SdJwtPresentationInputbuilder builder() {
    return new SdJwtPresentationInputbuilder();
  }

  /**
   * Builder class for creating instances of {@link SdJwtPresentationInput}.
   */
  public static class SdJwtPresentationInputbuilder {

    /**
     * The object being built
     */
    private final SdJwtPresentationInput presentationInput;

    /**
     * Constructs a new instance of SdJwtPresentationInputbuilder.
     */
    public SdJwtPresentationInputbuilder() {
      presentationInput = new SdJwtPresentationInput();
    }

    /**
     * Sets the token for the {@link SdJwtPresentationInput} being built.
     *
     * @param token the token to set, represented as a byte array
     * @return the current instance of the SdJwtPresentationInputbuilder for method chaining
     */
    public SdJwtPresentationInputbuilder token(byte[] token) {
      presentationInput.token = token;
      return this;
    }

    /**
     * Sets the nonce for the {@link SdJwtPresentationInput} being built.
     *
     * @param nonce the nonce to set, represented as a String
     * @return the current instance of the SdJwtPresentationInputbuilder for method chaining
     */
    public SdJwtPresentationInputbuilder nonce(String nonce) {
      presentationInput.nonce = nonce;
      return this;
    }

    /**
     * Sets the cryptographic signing algorithm for the {@code SdJwtPresentationInput} being built.
     *
     * @param algorithm the cryptographic signing algorithm to set, represented as an instance of {@link TokenSigningAlgorithm}
     * @return the current instance of {@code SdJwtPresentationInputbuilder} for method chaining
     */
    public SdJwtPresentationInputbuilder algorithm(
      TokenSigningAlgorithm algorithm
    ) {
      presentationInput.algorithm = algorithm;
      return this;
    }

    /**
     * Sets the disclosures for the {@link SdJwtPresentationInput} being built.
     *
     * @param disclosures the list of disclosures to set, represented as a List of Strings
     * @return the current instance of the SdJwtPresentationInputbuilder for method chaining
     */
    public SdJwtPresentationInputbuilder disclosures(List<String> disclosures) {
      presentationInput.disclosures = disclosures;
      return this;
    }

    /**
     * Sets the audience for the {@code SdJwtPresentationInput} being built.
     *
     * @param audience the audience to set, represented as a String
     * @return the current instance of the {@code SdJwtPresentationInputbuilder} for method chaining
     */
    public SdJwtPresentationInputbuilder audience(String audience) {
      presentationInput.audience = audience;
      return this;
    }

    /**
     * Finalizes the building process and returns the constructed instance of {@code SdJwtPresentationInput}.
     *
     * @return the fully constructed {@code SdJwtPresentationInput} with all specified properties set
     */
    public SdJwtPresentationInput build() {
      return presentationInput;
    }
  }
}

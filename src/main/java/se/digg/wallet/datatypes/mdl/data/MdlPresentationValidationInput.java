// SPDX-FileCopyrightText: 2025 Digg - Agency for Digital Government
//
// SPDX-License-Identifier: EUPL-1.2

package se.digg.wallet.datatypes.mdl.data;

import java.security.PrivateKey;

import lombok.Data;
import lombok.EqualsAndHashCode;
import lombok.NoArgsConstructor;
import se.digg.wallet.datatypes.common.PresentationValidationInput;

/**
 * MdlPresentationValidationInput is a specialized subclass of PresentationValidationInput, designed
 * to handle the validation input for mDL (mobile Driver's License) presentations. It extends the
 * functionality of the parent class by encapsulating additional fields specific to mDL validation
 * requirements, such as clientId, responseUri, and mdocGeneratedNonce.
 */
@EqualsAndHashCode(callSuper = true)
@Data
@NoArgsConstructor
public class MdlPresentationValidationInput extends PresentationValidationInput {

  /**
   * Constructs a new instance of {@code MdlPresentationValidationInput} by extracting relevant
   * fields from the provided {@code MdlPresentationInput} object. The constructor initializes the
   * parent class with the request nonce and sets the client ID, response URI, and mdoc generated
   * nonce specific to mDL presentations.
   *
   * @param presentationInput the {@code MdlPresentationInput} object containing the input data
   *        required to initialize this instance, including the client ID, response URI, and mdoc
   *        generated nonce
   */
  public MdlPresentationValidationInput(MdlPresentationInput presentationInput) {
    super(presentationInput.getNonce());
    this.clientId = presentationInput.getClientId();
    this.responseUri = presentationInput.getResponseUri();
    this.mdocGeneratedNonce = presentationInput.getMdocGeneratedNonce();
  }

  /** The presentation requester client ID (OpenID4VP) */
  private String clientId;
  /** The return URL for the presentation response */
  private String responseUri;
  /**
   * The wallet generated nonce included as the apu header parameter in the presentation response
   * JWT
   */
  private String mdocGeneratedNonce;
  /** Optional private key for MAC validation */
  private PrivateKey clientPrivateKey;

  /**
   * Creates and returns a new instance of {@code MdlPresentationValidationInputBuilder}. This
   * builder allows constructing instances of {@code MdlPresentationValidationInput} with
   * configurable options for its fields in a fluent and streamlined manner.
   *
   * @return a new instance of {@code MdlPresentationValidationInputBuilder} to construct an
   *         {@code MdlPresentationValidationInput} object.
   */
  public static MdlPresentationValidationInputBuilder builder() {
    return new MdlPresentationValidationInputBuilder();
  }

  /**
   * A builder class to construct instances of {@code MdlPresentationValidationInput} with various
   * configuration options. This builder provides a streamlined way to populate the necessary fields
   * of the {@code MdlPresentationValidationInput} object.
   */
  public static class MdlPresentationValidationInputBuilder {
    /** Object to build. */
    private MdlPresentationValidationInput presentationInput;

    /**
     * Default constructor for {@code MdlPresentationValidationInputBuilder}. Initializes a new
     * instance of {@code MdlPresentationValidationInput} which will be populated through the
     * builder configuration methods.
     */
    public MdlPresentationValidationInputBuilder() {
      presentationInput = new MdlPresentationValidationInput();
    }

    /**
     * Sets the client identifier for the {@code MdlPresentationValidationInput} being built.
     *
     * @param clientId the client identifier to be set
     * @return the current instance of {@code MdlPresentationValidationInputBuilder} to allow method
     *         chaining
     */
    public MdlPresentationValidationInputBuilder clientId(String clientId) {
      presentationInput.clientId = clientId;
      return this;
    }

    /**
     * Sets the response URI for the {@code MdlPresentationValidationInput} being built.
     *
     * @param responseUri the response URI to be set
     * @return the current instance of {@code MdlPresentationValidationInputBuilder} to allow method
     *         chaining
     */
    public MdlPresentationValidationInputBuilder responseUri(String responseUri) {
      presentationInput.responseUri = responseUri;
      return this;
    }

    /**
     * Sets the mdoc-generated nonce for the {@code MdlPresentationValidationInput} being built.
     *
     * @param mdocGeneratedNonce the mdoc-generated nonce to be set
     * @return the current instance of {@code MdlPresentationValidationInputBuilder} to allow method
     *         chaining
     */
    public MdlPresentationValidationInputBuilder mdocGeneratedNonce(String mdocGeneratedNonce) {
      presentationInput.mdocGeneratedNonce = mdocGeneratedNonce;
      return this;
    }

    /**
     * Sets the presentation requesters private key for the {@code MdlPresentationValidationInput}
     * being built. This is only required to validate Mac device authentication, supporting DH key
     * derivation
     *
     * @param clientPrivateKey the private key of the client to be set
     * @return the current instance of {@code MdlPresentationValidationInputBuilder} to allow method
     *         chaining
     */
    public MdlPresentationValidationInputBuilder clientPrivateKey(PrivateKey clientPrivateKey) {
      presentationInput.clientPrivateKey = clientPrivateKey;
      return this;
    }

    /**
     * Sets the nonce value for the {@code MdlPresentationValidationInput} being built.
     *
     * @param nonce the nonce value to be set
     * @return the current instance of {@code MdlPresentationValidationInputBuilder} to allow method
     *         chaining
     */
    public MdlPresentationValidationInputBuilder nonce(String nonce) {
      presentationInput.requestNonce = nonce;
      return this;
    }

    /**
     * Builds and returns the configured instance of {@code MdlPresentationValidationInput}.
     *
     * @return the fully configured {@code MdlPresentationValidationInput} instance
     */
    public MdlPresentationValidationInput build() {
      return presentationInput;
    }
  }
}

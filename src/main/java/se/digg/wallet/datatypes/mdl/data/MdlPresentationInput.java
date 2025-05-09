// SPDX-FileCopyrightText: 2025 diggsweden/eudiw-wallet-token-lib
//
// SPDX-License-Identifier: EUPL-1.2

package se.digg.wallet.datatypes.mdl.data;

import java.security.PublicKey;
import java.util.List;
import java.util.Map;
import lombok.Getter;
import se.digg.wallet.datatypes.common.PresentationInput;
import se.digg.wallet.datatypes.common.TokenSigningAlgorithm;

/**
 * MdlPresentationInput is a specialized implementation of the PresentationInput class tailored for
 * mDL (mobile Driver's License) presentations. It encapsulates specific inputs and metadata
 * required for constructing an mDL presentation. This class also provides a builder for convenient
 * construction of its instances.
 */
@Getter
public class MdlPresentationInput
    extends PresentationInput<Map<String, List<String>>> {

  /** The presentation requester client ID (See OpenID4VP) */
  private String clientId;
  /**
   * A nonce value generated by the presenting wallet included as the apu header parameter value of
   * the response JWT (OpenID4VP)
   */
  private String mdocGeneratedNonce;
  /** The response URL where the presentation response is delivered */
  private String responseUri;
  /** Client MAC key derivation key **/
  private PublicKey clientPublicKey;
  /**
   * Set to true to use MAC device authentication. If set to true clientPublicKey MUST be set
   */
  boolean macDeviceAuthentication = false;

  /**
   * Creates and returns a new instance of the {@link MdlPresentationInputBuilder} class. The
   * builder enables a step-by-step construction of an {@link MdlPresentationInput} object.
   *
   * @return a {@code MdlPresentationInputBuilder} instance for building
   *         {@code MdlPresentationInput} objects.
   */
  public static MdlPresentationInputBuilder builder() {
    return new MdlPresentationInputBuilder();
  }

  /**
   * Builder for creating instances of the {@link MdlPresentationInput} class.
   */
  public static class MdlPresentationInputBuilder {

    /** The object being built */
    final MdlPresentationInput mdlPresentationInput;

    /**
     * Constructs a new instance of the {@code MdlPresentationInputBuilder} class.
     */
    public MdlPresentationInputBuilder() {
      mdlPresentationInput = new MdlPresentationInput();
    }

    /**
     * Sets the token to be used in the {@code MdlPresentationInput} object being built.
     *
     * @param token the byte array representing the token
     * @return the {@code MdlPresentationInputBuilder} instance for method chaining
     */
    public MdlPresentationInputBuilder token(byte[] token) {
      mdlPresentationInput.token = token;
      return this;
    }

    /**
     * Sets the nonce to be used in the {@code MdlPresentationInput} object being built.
     *
     * @param nonce the string value representing the nonce
     * @return the {@code MdlPresentationInputBuilder} instance for method chaining
     */
    public MdlPresentationInputBuilder nonce(String nonce) {
      mdlPresentationInput.nonce = nonce;
      return this;
    }

    /**
     * Sets the client ID to be used in the {@code MdlPresentationInput} object being built.
     *
     * @param walletId the client ID represented as a string
     * @return the {@code MdlPresentationInputBuilder} instance for method chaining
     */
    public MdlPresentationInputBuilder clientId(String walletId) {
      mdlPresentationInput.clientId = walletId;
      return this;
    }

    /**
     * Sets the mdoc generated nonce to be used in the {@code MdlPresentationInput} object being
     * built.
     *
     * @param mdocGeneratedNonce the string value representing the mdoc generated nonce
     * @return the {@code MdlPresentationInputBuilder} instance for method chaining
     */
    public MdlPresentationInputBuilder mdocGeneratedNonce(
        String mdocGeneratedNonce) {
      mdlPresentationInput.mdocGeneratedNonce = mdocGeneratedNonce;
      return this;
    }

    /**
     * Sets the response URI to be used in the {@code MdlPresentationInput} object being built.
     *
     * @param responseUri the response URI represented as a string
     * @return the {@code MdlPresentationInputBuilder} instance for method chaining
     */
    public MdlPresentationInputBuilder responseUri(String responseUri) {
      mdlPresentationInput.responseUri = responseUri;
      return this;
    }

    /**
     * Sets the disclosures to be used in the {@code MdlPresentationInput} object being built.
     *
     * @param disclosures a map where the key is a namespace, and the value is a list of attribute
     *        names being disclosed
     * @return the {@code MdlPresentationInputBuilder} instance for method chaining
     */
    public MdlPresentationInputBuilder disclosures(
        Map<String, List<String>> disclosures) {
      mdlPresentationInput.disclosures = disclosures;
      return this;
    }

    /**
     * Sets the wallet signing algorithm to be used in the {@code MdlPresentationInput} object being
     * built.
     *
     * @param algorithm the {@code TokenSigningAlgorithm} specifying the signing algorithm to be
     *        used by the wallet
     * @return the {@code MdlPresentationInputBuilder} instance for method chaining
     */
    public MdlPresentationInputBuilder algorithm(
        TokenSigningAlgorithm algorithm) {
      mdlPresentationInput.algorithm = algorithm;
      return this;
    }

    /**
     * Sets the optional client public key to be used in the {@code MdlPresentationInput} object
     * being built. If this key is provided, this will enable derivation of a MAC key to provide a
     * MAC device key proof.
     *
     * @param clientPublicKey the {@code PublicKey} instance representing the client's public key
     * @return the {@code MdlPresentationInputBuilder} instance for method chaining
     */
    public MdlPresentationInputBuilder clientPublicKey(PublicKey clientPublicKey) {
      mdlPresentationInput.clientPublicKey = clientPublicKey;
      return this;
    }

    /**
     * Sets whether MAC (Message Authentication Code) device authentication should be enabled in the
     * {@code MdlPresentationInput} object being built.
     *
     * @param macDeviceAuthentication a boolean value indicating whether MAC device authentication
     *        should be enabled. If set to true, MAC device authentication will be used; otherwise,
     *        device signature will be applied (default false).
     * @return the {@code MdlPresentationInputBuilder} instance for method chaining.
     */
    public MdlPresentationInputBuilder macDeviceAuthentication(boolean macDeviceAuthentication) {
      mdlPresentationInput.macDeviceAuthentication = macDeviceAuthentication;
      return this;
    }

    /**
     * Builds and returns the fully constructed {@code MdlPresentationInput} object.
     *
     * @return the constructed {@code MdlPresentationInput} instance containing all the set
     *         properties.
     */
    public MdlPresentationInput build() {
      return mdlPresentationInput;
    }
  }
}

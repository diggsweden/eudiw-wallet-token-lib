// SPDX-FileCopyrightText: 2024 Digg - Agency for Digital Government
//
// SPDX-License-Identifier: EUPL-1.2

package se.digg.wallet.datatypes.sdjwt.process;

import java.security.PublicKey;
import java.time.Duration;
import java.util.List;
import lombok.Data;
import lombok.EqualsAndHashCode;
import se.digg.wallet.datatypes.common.TokenAttribute;
import se.digg.wallet.datatypes.common.TokenInput;
import se.digg.wallet.datatypes.common.TokenSigningAlgorithm;
import se.digg.wallet.datatypes.sdjwt.data.ClaimsWithDisclosure;
import se.swedenconnect.security.credential.PkiCredential;

/**
 * Represents an input object for generating an SD-JWT (Selective Disclosure-JSON Web Token).
 * Extends the functionality provided by the {@code TokenInput} class to include additional
 * fields and methods specific to SD-JWTs.
 */
@EqualsAndHashCode(callSuper = true)
@Data
public class SdJwtTokenInput extends TokenInput {

  /** Claims with associated disclosure data */
  private ClaimsWithDisclosure claimsWithDisclosure;
  /** The type identifier for the verifiable credential type represented in this SD-JWT */
  private String verifiableCredentialType;

  /**
   * Constructor for creating an SdJwtTokenInput instance.
   *
   * @param issuer the issuer of the token.
   * @param attributes the list of token attributes that are private and require disclosure by the wallet.
   * @param openAttributes the list of token attributes that are publicly accessible without disclosure.
   * @param issuerCredential the credential used by the issuer for signing and verification.
   * @param expirationDuration the duration after which the token expires.
   * @param algorithm the signing algorithm used for creating the token signature.
   * @param walletPublicKey the public key of the wallet intended to interact with the token.
   * @param claimsWithDisclosure the claims along with their respective disclosures.
   */
  public SdJwtTokenInput(
    String issuer,
    List<TokenAttribute> attributes,
    List<TokenAttribute> openAttributes,
    PkiCredential issuerCredential,
    Duration expirationDuration,
    TokenSigningAlgorithm algorithm,
    PublicKey walletPublicKey,
    ClaimsWithDisclosure claimsWithDisclosure
  ) {
    super(
      issuer,
      attributes,
      openAttributes,
      issuerCredential,
      expirationDuration,
      algorithm,
      walletPublicKey
    );
    this.claimsWithDisclosure = claimsWithDisclosure;
  }

  /**
   * Default constructor for the SdJwtTokenInput class.
   */
  public SdJwtTokenInput() {}

  /**
   * Provides a new instance of the SdJwtTokenInputBuilder, which is used for
   * configuring and building an SdJwtTokenInput object with the desired properties.
   *
   * @return a new instance of SdJwtTokenInputBuilder for constructing an SdJwtTokenInput.
   */
  public static SdJwtTokenInputBuilder sdJwtINputBuilder() {
    return new SdJwtTokenInputBuilder();
  }

  /**
   * Builder class for constructing instances of SdJwtTokenInput.
   */
  public static class SdJwtTokenInputBuilder {

    /**
     * The object being built
     */
    private final SdJwtTokenInput tokenInput;

    /**
     * Constructs a new instance of the SdJwtTokenInputBuilder class.
     */
    public SdJwtTokenInputBuilder() {
      tokenInput = new SdJwtTokenInput();
    }

    /**
     * Sets the claims with disclosure for the SdJwtTokenInput being built.
     *
     * @param claimsWithDisclosure the claims with disclosure object to set
     * @return the current instance of SdJwtTokenInputBuilder for method chaining
     */
    public SdJwtTokenInputBuilder claimsWithDisclosure(
      ClaimsWithDisclosure claimsWithDisclosure
    ) {
      tokenInput.claimsWithDisclosure = claimsWithDisclosure;
      return this;
    }

    /**
     * Sets the verifiable credential type for the SdJwtTokenInput being built.
     *
     * @param verifiableCredentialType the type of the verifiable credential to set
     * @return the current instance of SdJwtTokenInputBuilder for method chaining
     */
    public SdJwtTokenInputBuilder verifiableCredentialType(
      String verifiableCredentialType
    ) {
      tokenInput.verifiableCredentialType = verifiableCredentialType;
      return this;
    }

    /**
     * Sets the issuer for the SdJwtTokenInput being built.
     *
     * @param issuer the issuer of the token to set
     * @return the current instance of SdJwtTokenInputBuilder for method chaining
     */
    public SdJwtTokenInputBuilder issuer(String issuer) {
      tokenInput.issuer = issuer;
      return this;
    }

    /**
     * Sets the list of attributes for the SdJwtTokenInput being built.
     *
     * @param attributes a list of {@link TokenAttribute} objects to set as the token attributes
     * @return the current instance of SdJwtTokenInputBuilder for method chaining
     */
    public SdJwtTokenInputBuilder attributes(List<TokenAttribute> attributes) {
      tokenInput.attributes = attributes;
      return this;
    }

    /**
     * Sets a list of open attributes for the SdJwtTokenInput being built.
     *
     * @param openAttributes a list of {@link TokenAttribute} objects to define open claims
     *                       that will be included in the token without selective disclosure
     * @return the current instance of SdJwtTokenInputBuilder for method chaining
     */
    public SdJwtTokenInputBuilder openAttributes(
      List<TokenAttribute> openAttributes
    ) {
      tokenInput.openAttributes = openAttributes;
      return this;
    }

    /**
     * Sets the issuer credential for the SdJwtTokenInput being built.
     *
     * @param issuerCredential the {@link PkiCredential} representing the issuer's credentials to be used for
     *                         signing and verification of the token
     * @return the current instance of SdJwtTokenInputBuilder for method chaining
     */
    public SdJwtTokenInputBuilder issuerCredential(
      PkiCredential issuerCredential
    ) {
      tokenInput.issuerCredential = issuerCredential;
      return this;
    }

    /**
     * Sets the expiration duration for the SdJwtTokenInput being built.
     *
     * @param expirationDuration the {@link Duration} representing the time period until the token expires
     * @return the current instance of {@code SdJwtTokenInputBuilder} for method chaining
     */
    public SdJwtTokenInputBuilder expirationDuration(
      Duration expirationDuration
    ) {
      tokenInput.expirationDuration = expirationDuration;
      return this;
    }

    /**
     * Sets the token signing algorithm for the SdJwtTokenInput being built.
     *
     * @param algorithm the {@link TokenSigningAlgorithm} to be used for signing the token
     * @return the current instance of {@code SdJwtTokenInputBuilder} for method chaining
     */
    public SdJwtTokenInputBuilder algorithm(TokenSigningAlgorithm algorithm) {
      tokenInput.algorithm = algorithm;
      return this;
    }

    /**
     * Sets the wallet public key for the SdJwtTokenInput being built.
     *
     * @param walletPublicKey the {@link PublicKey} to set as the wallet's public key,
     *                        which will be used for token confirmation.
     * @return the current instance of {@code SdJwtTokenInputBuilder} for method chaining.
     */
    public SdJwtTokenInputBuilder walletPublicKey(PublicKey walletPublicKey) {
      tokenInput.walletPublicKey = walletPublicKey;
      return this;
    }

    /**
     * Creates and returns a new instance of {@code SdJwtTokenInput} with the properties
     * configured using the builder methods of {@code SdJwtTokenInputBuilder}.
     *
     * @return a new and configured instance of {@code SdJwtTokenInput}
     */
    public SdJwtTokenInput build() {
      // Here you might want to validate your tokenInput object
      // to ensure its consistency before returning it.
      return tokenInput;
    }
  }
}

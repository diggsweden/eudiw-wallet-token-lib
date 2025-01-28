// SPDX-FileCopyrightText: 2024 Digg - Agency for Digital Government
//
// SPDX-License-Identifier: EUPL-1.2

package se.digg.wallet.datatypes.sdjwt.process;

import com.nimbusds.jose.JWSAlgorithm;
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

@EqualsAndHashCode(callSuper = true)
@Data
public class SdJwtTokenInput extends TokenInput {

  private ClaimsWithDisclosure claimsWithDisclosure;
  private String verifiableCredentialType;

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

  public SdJwtTokenInput() {}

  public static SdJwtTokenInputBuilder sdJwtINputBuilder() {
    return new SdJwtTokenInputBuilder();
  }

  public static class SdJwtTokenInputBuilder {

    private final SdJwtTokenInput tokenInput;

    public SdJwtTokenInputBuilder() {
      tokenInput = new SdJwtTokenInput();
    }

    public SdJwtTokenInputBuilder claimsWithDisclosure(
      ClaimsWithDisclosure claimsWithDisclosure
    ) {
      tokenInput.claimsWithDisclosure = claimsWithDisclosure;
      return this;
    }

    public SdJwtTokenInputBuilder verifiableCredentialType(
      String verifiableCredentialType
    ) {
      tokenInput.verifiableCredentialType = verifiableCredentialType;
      return this;
    }

    public SdJwtTokenInputBuilder issuer(String issuer) {
      tokenInput.issuer = issuer;
      return this;
    }

    public SdJwtTokenInputBuilder attributes(List<TokenAttribute> attributes) {
      tokenInput.attributes = attributes;
      return this;
    }

    public SdJwtTokenInputBuilder openAttributes(
      List<TokenAttribute> openAttributes
    ) {
      tokenInput.openAttributes = openAttributes;
      return this;
    }

    public SdJwtTokenInputBuilder issuerCredential(
      PkiCredential issuerCredential
    ) {
      tokenInput.issuerCredential = issuerCredential;
      return this;
    }

    public SdJwtTokenInputBuilder expirationDuration(
      Duration expirationDuration
    ) {
      tokenInput.expirationDuration = expirationDuration;
      return this;
    }

    public SdJwtTokenInputBuilder algorithm(TokenSigningAlgorithm algorithm) {
      tokenInput.algorithm = algorithm;
      return this;
    }

    public SdJwtTokenInputBuilder walletPublicKey(PublicKey walletPublicKey) {
      tokenInput.walletPublicKey = walletPublicKey;
      return this;
    }

    public SdJwtTokenInput build() {
      // Here you might want to validate your tokenInput object
      // to ensure its consistency before returning it.
      return tokenInput;
    }
  }
}

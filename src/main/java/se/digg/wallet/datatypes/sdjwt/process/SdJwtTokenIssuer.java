// SPDX-FileCopyrightText: 2024 Digg - Agency for Digital Government
//
// SPDX-License-Identifier: EUPL-1.2

package se.digg.wallet.datatypes.sdjwt.process;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.nimbusds.jose.JOSEException;
import java.nio.charset.StandardCharsets;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateEncodingException;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;
import lombok.Setter;
import se.digg.wallet.datatypes.common.TokenAttribute;
import se.digg.wallet.datatypes.common.TokenDigestAlgorithm;
import se.digg.wallet.datatypes.common.TokenIssuer;
import se.digg.wallet.datatypes.common.TokenIssuingException;
import se.digg.wallet.datatypes.common.TokenSigningAlgorithm;
import se.digg.wallet.datatypes.sdjwt.JSONUtils;
import se.digg.wallet.datatypes.sdjwt.data.ClaimsWithDisclosure;
import se.digg.wallet.datatypes.sdjwt.data.Disclosure;
import se.digg.wallet.datatypes.sdjwt.data.SdJwt;
import se.swedenconnect.security.credential.PkiCredential;

/**
 * A concrete implementation of the {@link TokenIssuer} interface responsible for issuing SD-JWT tokens.
 * <p>
 * This class handles the generation of signed (SD-JWT) tokens with selective disclosure.
 * The implementation ensures tokens are generated in compliance with the specified signing algorithm,
 * issuer credentials, and attributes provided in the {@link SdJwtTokenInput}. It supports customizing
 * legacy behavior for the SD-JWT header type.
 */
@Setter
public class SdJwtTokenIssuer implements TokenIssuer<SdJwtTokenInput> {

  private boolean legacySdJwtHeaderType = false;

  @Override
  public byte[] issueToken(SdJwtTokenInput tokenInput)
    throws TokenIssuingException {
    if (tokenInput == null) {
      throw new TokenIssuingException("TokenInput cannot be null");
    }
    try {
      TokenSigningAlgorithm algorithm = tokenInput.getAlgorithm();
      TokenDigestAlgorithm digestAlgorithm = algorithm.getDigestAlgorithm();
      ClaimsWithDisclosure claimsWithDisclosure =
        tokenInput.getClaimsWithDisclosure();
      if (claimsWithDisclosure == null) {
        // Construct from InputAttributes
        ClaimsWithDisclosure.ClaimsWithDisclosureBuilder cwdBuilder =
          ClaimsWithDisclosure.builder(digestAlgorithm);
        List<TokenAttribute> tokenAttributes = Optional.ofNullable(
          tokenInput.getAttributes()
        ).orElse(new ArrayList<>());
        for (TokenAttribute tokenAttribute : tokenAttributes) {
          cwdBuilder.disclosure(new Disclosure(tokenAttribute));
        }
        List<TokenAttribute> openAttributes = Optional.ofNullable(
          tokenInput.getOpenAttributes()
        ).orElse(new ArrayList<>());
        for (TokenAttribute openAttribute : openAttributes) {
          cwdBuilder.openClaim(
            openAttribute.getType().getAttributeName(),
            openAttribute.getValue()
          );
        }
        claimsWithDisclosure = cwdBuilder.build();
      }

      PkiCredential issuerCredential = tokenInput.getIssuerCredential();
      SdJwt sdJwt = SdJwt.builder(tokenInput.getIssuer(), digestAlgorithm)
        .legacySdJwtType(legacySdJwtHeaderType)
        .claimsWithDisclosure(claimsWithDisclosure)
        .confirmationKey(
          JSONUtils.getJWKfromPublicKey(tokenInput.getWalletPublicKey())
        )
        .verifiableCredentialType(tokenInput.getVerifiableCredentialType())
        .build(
          issuerCredential,
          tokenInput.getExpirationDuration(),
          algorithm.getJwsAlgorithm(),
          algorithm.jwsSigner(issuerCredential.getPrivateKey()),
          issuerCredential.getName()
        );
      return sdJwt
        .unprotectedPresentation(null)
        .getBytes(StandardCharsets.UTF_8);
    } catch (JsonProcessingException e) {
      throw new TokenIssuingException("Error parsing token request", e);
    } catch (
      CertificateEncodingException | NoSuchAlgorithmException | JOSEException e
    ) {
      throw new TokenIssuingException("Token signing failed", e);
    } catch (Exception e) {
      throw new TokenIssuingException("Failed to issue token", e);
    }
  }
}

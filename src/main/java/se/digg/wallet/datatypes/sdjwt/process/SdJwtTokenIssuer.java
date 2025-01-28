package se.digg.wallet.datatypes.sdjwt.process;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.nimbusds.jose.JOSEException;
import se.digg.wallet.datatypes.common.*;
import se.digg.wallet.datatypes.sdjwt.JSONUtils;
import se.digg.wallet.datatypes.sdjwt.data.ClaimsWithDisclosure;
import se.digg.wallet.datatypes.sdjwt.data.Disclosure;
import se.digg.wallet.datatypes.sdjwt.data.SdJwt;
import se.swedenconnect.security.credential.PkiCredential;

import java.nio.charset.StandardCharsets;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateEncodingException;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;

/**
 * Description
 */
public class SdJwtTokenIssuer implements TokenIssuer<SdJwtTokenInput> {
  @Override public byte[] issueToken(SdJwtTokenInput tokenInput) throws TokenIssuingException {
    if (tokenInput == null) {
      throw new TokenIssuingException("TokenInput cannot be null");
    }
    try {
      TokenSigningAlgorithm algorithm = tokenInput.getAlgorithm();
      TokenDigestAlgorithm digestAlgorithm = algorithm.getDigestAlgorithm();
      ClaimsWithDisclosure claimsWithDisclosure = tokenInput.getClaimsWithDisclosure();
      if (claimsWithDisclosure == null) {
        // Construct from InputAttributes
        ClaimsWithDisclosure.ClaimsWithDisclosureBuilder cwdBuilder = ClaimsWithDisclosure.builder(digestAlgorithm.getJdkName());
        List<TokenAttribute> tokenAttributes = Optional.ofNullable(tokenInput.getAttributes()).orElse(new ArrayList<>());
        for (TokenAttribute tokenAttribute : tokenAttributes) {
          cwdBuilder.disclosure(new Disclosure(tokenAttribute));
        }
        List<TokenAttribute> openAttributes = Optional.ofNullable(tokenInput.getOpenAttributes()).orElse(new ArrayList<>());
        for (TokenAttribute openAttribute : openAttributes) {
          cwdBuilder.openClaim(openAttribute.getName(), openAttribute.getValue());
        }
        claimsWithDisclosure = cwdBuilder.build();
      }

      PkiCredential issuerCredential = tokenInput.getIssuerCredential();
      SdJwt sdJwt = SdJwt.issuerSignedBuilder(tokenInput.getIssuer(), digestAlgorithm.getJdkName())
        .claimsWithDisclosure(claimsWithDisclosure)
        .confirmationKey(JSONUtils.getJWKfromPublicKey(tokenInput.getWalletPublicKey()))
        .verifiableCredentialType(tokenInput.getVerifiableCredentialType())
        .build(issuerCredential, tokenInput.getExpirationDuration(), algorithm.getJwsAlgorithm(), algorithm.jwsSigner(
          issuerCredential.getPrivateKey()), issuerCredential.getName());
      return sdJwt.unprotectedPresentation(null).getBytes(StandardCharsets.UTF_8);
    }
    catch (JsonProcessingException e) {
      throw new TokenIssuingException("Error parsing token request", e);
    }
    catch (CertificateEncodingException | NoSuchAlgorithmException | JOSEException e) {
      throw new TokenIssuingException("Token signing failed", e);
    }
  }
}

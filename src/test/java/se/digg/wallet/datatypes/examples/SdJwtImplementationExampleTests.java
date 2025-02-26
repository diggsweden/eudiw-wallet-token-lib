// SPDX-FileCopyrightText: 2024 diggsweden/eudiw-wallet-token-lib
//
// SPDX-License-Identifier: EUPL-1.2

package se.digg.wallet.datatypes.examples;

import com.nimbusds.jose.jwk.ECKey;

import java.security.PublicKey;
import java.security.Security;
import java.time.Duration;
import java.util.List;

import lombok.extern.slf4j.Slf4j;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import se.digg.wallet.datatypes.common.TestCredentials;
import se.digg.wallet.datatypes.common.TokenAttribute;
import se.digg.wallet.datatypes.common.TokenAttributeType;
import se.digg.wallet.datatypes.common.TokenSigningAlgorithm;
import se.digg.wallet.datatypes.common.TrustedKey;
import se.digg.wallet.datatypes.sdjwt.JSONUtils;
import se.digg.wallet.datatypes.sdjwt.data.SdJwtPresentationInput;
import se.digg.wallet.datatypes.sdjwt.data.SdJwtPresentationValidationInput;
import se.digg.wallet.datatypes.sdjwt.process.SdJwtPresentationValidator;
import se.digg.wallet.datatypes.sdjwt.process.SdJwtTokenInput;
import se.digg.wallet.datatypes.sdjwt.process.SdJwtTokenIssuer;
import se.digg.wallet.datatypes.sdjwt.process.SdJwtTokenPresenter;
import se.digg.wallet.datatypes.sdjwt.process.SdJwtTokenValidationResult;
import se.digg.wallet.datatypes.sdjwt.process.SdJwtTokenValidator;
import se.swedenconnect.security.credential.PkiCredential;

@Slf4j
public class SdJwtImplementationExampleTests {

  static PkiCredential issuerCredential;
  static ECKey walletKeyPair;
  static PublicKey walletPublicKey;
  static List<TrustedKey> trustedKeys;

  @BeforeAll
  static void setUp() throws Exception {
    if (Security.getProvider("BC") == null) {
      Security.addProvider(new BouncyCastleProvider());
    }
    issuerCredential = TestCredentials.p256_issuerCredential;
    walletKeyPair = TestCredentials.p256_walletKey;
    walletPublicKey = walletKeyPair.toPublicKey();
    trustedKeys = List.of(
        TrustedKey.builder()
            .certificate(issuerCredential.getCertificate())
            .build());
  }

  @Test
  void sdJwtExampleTest() throws Exception {
    byte[] sdJwtToken = issueSdJwt();
    log.info("Issued token:\n{}", new String(sdJwtToken));
    validateSDJwtToken(sdJwtToken, trustedKeys);
    byte[] presentSdJwtToken = presentSdJwtToken(sdJwtToken);
    log.info("Presented token:\n{}", new String(presentSdJwtToken));
    validateSdJwtPresentation(presentSdJwtToken,
        trustedKeys);
  }

  byte[] issueSdJwt() throws Exception {
    SdJwtTokenInput tokenInput = SdJwtTokenInput.sdJwtINputBuilder()
        .algorithm(TokenSigningAlgorithm.ECDSA_256)
        .issuerCredential(issuerCredential)
        .walletPublicKey(walletPublicKey)
        .expirationDuration(Duration.ofHours(12))
        .verifiableCredentialType("eu.europa.ec.eudi.pid.1")
        .issuer("https://example.com/issuer")
        .attributes(List.of(
            TokenAttribute.builder()
                .type(new TokenAttributeType("given_name"))
                .value("John")
                .build(),
            TokenAttribute.builder()
                .type(new TokenAttributeType("family_name"))
                .value("Doe")
                .build()))
        .build();
    SdJwtTokenIssuer tokenIssuer = new SdJwtTokenIssuer();
    return tokenIssuer.issueToken(tokenInput);
  }

  SdJwtTokenValidationResult validateSDJwtToken(byte[] sdJwtToken, List<TrustedKey> trustedKeys)
      throws Exception {
    SdJwtTokenValidator tokenValidator = new SdJwtTokenValidator();
    return tokenValidator.validateToken(
        sdJwtToken,
        trustedKeys);
  }

  byte[] presentSdJwtToken(byte[] token) throws Exception {
    SdJwtTokenPresenter tokenPresenter = new SdJwtTokenPresenter();

    SdJwtPresentationInput presentationInput = SdJwtPresentationInput.builder()
        .algorithm(TokenSigningAlgorithm.ECDSA_256)
        .token(token)
        .nonce("1234567890_nonce")
        .audience("https://example.com/aud")
        .disclosures(List.of("given_name", "family_name"))
        .build();
    return tokenPresenter.presentToken(presentationInput, walletKeyPair.toPrivateKey());
  }

  SdJwtTokenValidationResult validateSdJwtPresentation(byte[] sdJwtPresentation,
      List<TrustedKey> trustedKeys) throws Exception {
    SdJwtPresentationValidator sdJwtPresentationValidator = new SdJwtPresentationValidator();
    return sdJwtPresentationValidator.validatePresentation(
        sdJwtPresentation,
        SdJwtPresentationValidationInput.builder()
            .requestNonce("1234567890_nonce")
            .audience("https://example.com/aud")
            .build(),
        trustedKeys);
  }

  /**
   * Illustrates and test the use case where SD-JWT is used without any selective disclosures
   *
   * @throws Exception on errors
   */
  @Test
  void issueAndPresentSdJwtWithNoSelectiveDisclosure() throws Exception {
    SdJwtTokenInput tokenInput = SdJwtTokenInput.sdJwtINputBuilder()
        .algorithm(TokenSigningAlgorithm.ECDSA_256)
        .issuerCredential(issuerCredential)
        .walletPublicKey(walletPublicKey)
        .expirationDuration(Duration.ofHours(12))
        .verifiableCredentialType("eu.europa.ec.eudi.pid.1")
        .issuer("https://example.com/issuer")
        .openAttributes(List.of(
            TokenAttribute.builder()
                .type(new TokenAttributeType("given_name"))
                .value("John")
                .build(),
            TokenAttribute.builder()
                .type(new TokenAttributeType("family_name"))
                .value("Doe")
                .build()))
        .build();
    SdJwtTokenIssuer tokenIssuer = new SdJwtTokenIssuer();
    final byte[] issuedToken = tokenIssuer.issueToken(tokenInput);
    log.info("Issued token without disclosures:\n{}", new String(issuedToken));
    SdJwtTokenValidator tokenValidator = new SdJwtTokenValidator();
    tokenValidator.validateToken(issuedToken, trustedKeys);
    SdJwtTokenPresenter tokenPresenter = new SdJwtTokenPresenter();
    byte[] presentSdJwtToken = tokenPresenter.presentToken(SdJwtPresentationInput.builder()
        .disclosures(List.of())
        .algorithm(TokenSigningAlgorithm.ECDSA_256)
        .token(issuedToken)
        .nonce("1234567890_nonce")
        .audience("https://example.com/aud")
        .build(), walletKeyPair.toPrivateKey());
    log.info("Presented token without disclosures:\n{}", new String(presentSdJwtToken));
    SdJwtTokenValidationResult presentationValidationResult =
        validateSdJwtPresentation(presentSdJwtToken,
            trustedKeys);
    log.info("Disclosed payload: \n{}", JSONUtils.JSON_MAPPER.writerWithDefaultPrettyPrinter()
        .writeValueAsString(
            presentationValidationResult.getDisclosedTokenPayload().toJSONObject()));
    presentationValidationResult
        .getDisclosedAttributes();
    log.info(
        "Disclosed attributes:\n{}",
        String.join(
            "\n",
            presentationValidationResult
                .getDisclosedAttributes()
                .entrySet()
                .stream()
                .map(e -> e.getKey() + " -> " + e.getValue())
                .toList()));
  }
}

// SPDX-FileCopyrightText: 2024 Digg - Agency for Digital Government
//
// SPDX-License-Identifier: EUPL-1.2

package se.digg.wallet.datatypes.examples;

import com.nimbusds.jose.jwk.ECKey;

import java.security.PublicKey;
import java.security.Security;
import java.time.Duration;
import java.util.Collections;
import java.util.List;

import lombok.extern.slf4j.Slf4j;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.util.encoders.Hex;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import se.digg.wallet.datatypes.common.TestCredentials;
import se.digg.wallet.datatypes.common.TokenAttribute;
import se.digg.wallet.datatypes.common.TokenAttributeNameSpace;
import se.digg.wallet.datatypes.common.TokenAttributeType;
import se.digg.wallet.datatypes.common.TokenInput;
import se.digg.wallet.datatypes.common.TokenSigningAlgorithm;
import se.digg.wallet.datatypes.common.TrustedKey;
import se.digg.wallet.datatypes.mdl.data.MdlPresentationInput;
import se.digg.wallet.datatypes.mdl.data.MdlPresentationValidationInput;
import se.digg.wallet.datatypes.mdl.process.MdlIssuerSignedValidationResult;
import se.digg.wallet.datatypes.mdl.process.MdlIssuerSignedValidator;
import se.digg.wallet.datatypes.mdl.process.MdlPresentationValidationResult;
import se.digg.wallet.datatypes.mdl.process.MdlPresentationValidator;
import se.digg.wallet.datatypes.mdl.process.MdlTokenIssuer;
import se.digg.wallet.datatypes.mdl.process.MdlTokenPresenter;
import se.swedenconnect.security.credential.PkiCredential;

@Slf4j
public class MdlImplementationExampleTests {

  static PkiCredential issuerCredential;
  static ECKey walletKeyPair;
  static ECKey clientKeyPair;
  static PublicKey walletPublicKey;
  static List<TrustedKey> trustedKeys;

  @BeforeAll
  static void setUp() throws Exception {
    if (Security.getProvider("BC") == null) {
      Security.addProvider(new BouncyCastleProvider());
    }
    issuerCredential = TestCredentials.p256_issuerCredential;
    clientKeyPair = TestCredentials.p256_clientKey;
    walletKeyPair = TestCredentials.p256_walletKey;
    walletPublicKey = walletKeyPair.toPublicKey();
    trustedKeys = List.of(
        TrustedKey.builder()
            .certificate(issuerCredential.getCertificate())
            .build());
  }

  @Test
  void sdJwtExampleTest() throws Exception {
    byte[] mdlToken = issueMdlToken();
    log.info("Issued token:\n{}", Hex.toHexString(mdlToken));
    validateMdlToken(mdlToken, trustedKeys);
    byte[] presentMdlToken = presentMdlToken(mdlToken);
    log.info("Presented token:\n{}", Hex.toHexString(presentMdlToken));
    validateMdlPresentation(presentMdlToken,
        trustedKeys);
    byte[] presentMdlTokenWithMac = presentMdlTokenWithMac(mdlToken);
    log.info("Presented token with MAC:\n{}", Hex.toHexString(presentMdlTokenWithMac));
    validateMdocPresentationWithMac(
        presentMdlTokenWithMac, trustedKeys);
  }

  byte[] issueMdlToken() throws Exception {
    TokenInput tokenInput = TokenInput.builder()
        .algorithm(TokenSigningAlgorithm.ECDSA_256)
        .issuerCredential(issuerCredential)
        .walletPublicKey(walletPublicKey)
        .expirationDuration(Duration.ofHours(12))
        .attributes(List.of(
            TokenAttribute.builder()
                .type(new TokenAttributeType(TokenAttributeNameSpace.EUDI_WALLET_PID.getId(),
                    "given_name"))
                .value("John")
                .build(),
            TokenAttribute.builder()
                .type(new TokenAttributeType(TokenAttributeNameSpace.EUDI_WALLET_PID.getId(),
                    "family_name"))
                .value("Doe")
                .build()))
        .build();
    MdlTokenIssuer tokenIssuer = new MdlTokenIssuer();
    return tokenIssuer.issueToken(tokenInput);
  }

  MdlIssuerSignedValidationResult validateMdlToken(byte[] mdlToken, List<TrustedKey> trustedKeys)
      throws Exception {
    MdlIssuerSignedValidator tokenValidator = new MdlIssuerSignedValidator();
    return tokenValidator.validateToken(mdlToken, trustedKeys);
  }

  byte[] presentMdlToken(byte[] token) throws Exception {
    MdlTokenPresenter tokenPresenter = new MdlTokenPresenter();

    MdlPresentationInput presentationInput = MdlPresentationInput.builder()
        .algorithm(TokenSigningAlgorithm.ECDSA_256)
        .token(token)
        .nonce("1234567890_nonce")
        .responseUri("https://example.com/aud")
        .clientId("https://example.com/client")
        .mdocGeneratedNonce("0987654321_walletNonce")
        .disclosures(Collections.singletonMap(TokenAttributeNameSpace.EUDI_WALLET_PID.getId(),
            List.of("given_name", "family_name")))
        .build();
    return tokenPresenter.presentToken(presentationInput, walletKeyPair.toPrivateKey());
  }

  MdlPresentationValidationResult validateMdlPresentation(byte[] sdJwtPresentation,
      List<TrustedKey> trustedKeys) throws Exception {
    MdlPresentationValidator sdJwtPresentationValidator = new MdlPresentationValidator();
    return sdJwtPresentationValidator.validatePresentation(sdJwtPresentation,
        MdlPresentationValidationInput.builder()
            .nonce("1234567890_nonce")
            .responseUri("https://example.com/aud")
            .clientId("https://example.com/client")
            .mdocGeneratedNonce("0987654321_walletNonce")
            .build(),
        trustedKeys);
  }

  byte[] presentMdlTokenWithMac(byte[] token) throws Exception {
    MdlTokenPresenter tokenPresenter = new MdlTokenPresenter();

    MdlPresentationInput presentationInput = MdlPresentationInput.builder()
        .algorithm(TokenSigningAlgorithm.ECDSA_256)
        .token(token)
        .nonce("1234567890_nonce")
        .responseUri("https://example.com/aud")
        .clientId("https://example.com/client")
        .mdocGeneratedNonce("0987654321_walletNonce")
        .clientPublicKey(clientKeyPair.toPublicKey())
        .macDeviceAuthentication(true)
        .disclosures(Collections.singletonMap(TokenAttributeNameSpace.EUDI_WALLET_PID.getId(),
            List.of("given_name", "family_name")))
        .build();
    return tokenPresenter.presentToken(presentationInput, walletKeyPair.toPrivateKey());
  }

  MdlPresentationValidationResult validateMdocPresentationWithMac(byte[] sdJwtPresentation,
      List<TrustedKey> trustedKeys) throws Exception {
    MdlPresentationValidator sdJwtPresentationValidator = new MdlPresentationValidator();
    return sdJwtPresentationValidator.validatePresentation(sdJwtPresentation,
        MdlPresentationValidationInput.builder()
            .nonce("1234567890_nonce")
            .responseUri("https://example.com/aud")
            .clientId("https://example.com/client")
            .mdocGeneratedNonce("0987654321_walletNonce")
            .clientPrivateKey(clientKeyPair.toPrivateKey())
            .build(),
        trustedKeys);
  }
}

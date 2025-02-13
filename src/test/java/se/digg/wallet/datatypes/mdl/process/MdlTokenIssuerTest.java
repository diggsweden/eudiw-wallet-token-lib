// SPDX-FileCopyrightText: 2024 Digg - Agency for Digital Government
//
// SPDX-License-Identifier: EUPL-1.2

package se.digg.wallet.datatypes.mdl.process;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Map;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.nimbusds.jose.JOSEObjectType;
import com.nimbusds.jose.jwk.ECKey;
import lombok.extern.slf4j.Slf4j;
import org.bouncycastle.util.encoders.Hex;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import se.digg.wallet.datatypes.common.*;
import se.digg.wallet.datatypes.mdl.data.*;
import se.digg.cose.AlgorithmID;
import se.digg.cose.COSEKey;
import se.digg.wallet.datatypes.sdjwt.JSONUtils;
import se.digg.wallet.datatypes.sdjwt.data.SdJwt;
import se.digg.wallet.datatypes.sdjwt.process.SdJwtTokenInput;
import se.digg.wallet.datatypes.sdjwt.process.SdJwtTokenIssuer;
import se.digg.wallet.datatypes.sdjwt.process.SdJwtTokenValidationResult;
import se.digg.wallet.datatypes.sdjwt.process.SdJwtTokenValidator;
import se.swedenconnect.security.credential.PkiCredential;

@Slf4j
class MdlTokenIssuerTest {

  static PkiCredential issuerCredential;
  static String pidNameSpace;
  static Map<String, List<String>> selectedDisclosures;
  static ECKey walletKey;


  @BeforeAll
  static void setUp() {
    issuerCredential = TestCredentials.p256_issuerCredential;
    pidNameSpace = "eu.europa.ec.eudi.pid.1";
    selectedDisclosures = Collections.singletonMap("eu.europa.ec.eudi.pid.1", List.of(
      "issuance_date",
      "issuing_country",
      "given_name",
      "family_name",
      "issuing_authority"
    ));
    walletKey = TestCredentials.p256_walletKey;
  }

  @Test
  void issueCredentialTest() throws Exception {
    COSEKey deviceKey = COSEKey.generateKey(AlgorithmID.ECDSA_256);

    TokenInput tokenInput = TokenInput.builder()
      .issuerCredential(issuerCredential)
      .algorithm(TokenSigningAlgorithm.ECDSA_256)
      .expirationDuration(Duration.ofDays(1))
      .walletPublicKey(deviceKey.AsPublicKey())
      .attributes(TestData.defaultPidUserAttributes)
      .build();
    MdlTokenIssuer tokenIssuer = new MdlTokenIssuer(true);
    byte[] token = tokenIssuer.issueToken(tokenInput);
    log.info("Issued mdL token: \n{}", Hex.toHexString(token));

    // Validate Issuer Signed Token
    MdlIssuerSignedValidator validator = new MdlIssuerSignedValidator();
    TokenValidationResult validationResult =
      validator.validateToken(
        token,
        List.of(
          TrustedKey.builder()
            .certificate(issuerCredential.getCertificate())
            .build()
        )
      );
    log.info("Token validation passed");

    // Make presentation
    PresentationInput<?> presentationInput = MdlPresentationInput.builder()
      .token(token)
      .clientId("https://example.com/client")
      .responseUri("https://example.com/response")
      .nonce("abcdefgh1234567890")
      .mdocGeneratedNonce("MTIzNDU2Nzg5MGFiY2RlZmdo")
      .algorithm(TokenSigningAlgorithm.ECDSA_256)
      .disclosures(selectedDisclosures)
      .build();
    TokenPresenter<?> tokenPresenter = new MdlTokenPresenter();
    byte[] presentedToken = tokenPresenter.presentToken(presentationInput, deviceKey.AsPrivateKey());
    log.info("Presented mdL token: \n{}", Hex.toHexString(presentedToken));

    // Parse presentation
    DeviceResponse deviceResponse = DeviceResponse.deserialize(presentedToken);
    byte[] parseResponseCbor = CBORUtils.CBOR_MAPPER.writeValueAsBytes(deviceResponse);
    log.info("Parsed presentation token CBOR:\n{}", Hex.toHexString(parseResponseCbor));
    Assertions.assertArrayEquals(presentedToken, parseResponseCbor);
    log.info("Presentation token parsed");

    MdlPresentationValidator presentationValidator = new MdlPresentationValidator();
    TokenValidationResult tokenValidationResult = presentationValidator.validatePresentation(
      presentedToken,
      new MdlPresentationValidationInput((MdlPresentationInput) presentationInput),
      null
    );
    log.info("Validated and pared presentation token content:\n{}", CBORUtils.cborToPrettyJson(presentedToken));
    log.info("Disclosed attributes:\n{}", String.join("\n", tokenValidationResult.getDisclosedAttributes().entrySet().stream()
      .map(e -> e.getKey() + " -> " + e.getValue())
      .toList()));

  }


  // Test cases

  @Test
  void testCases() throws Exception {

    performTest("Default EC issuer key setup",
      TokenInput.builder()
        .algorithm(TokenSigningAlgorithm.ECDSA_256)
        .issuer("http://example.com/issuer")
        .issuerCredential(issuerCredential)
        .walletPublicKey(walletKey.toPublicKey())
        .expirationDuration(Duration.ofDays(1))
        .attributes(TestData.defaultPidUserAttributes)
        .build(), null);

    performTest("RSA Issuer key",
      TokenInput.builder()
        .algorithm(TokenSigningAlgorithm.RSA_PSS_512)
        .issuer("http://example.com/issuer")
        .issuerCredential(TestCredentials.rsa_issuerCredential)
        .walletPublicKey(walletKey.toPublicKey())
        .expirationDuration(Duration.ofDays(1))
        .attributes(TestData.defaultPidUserAttributes)
        .build(), null);

    performTest("Legacy SD-JWT type",
      TokenInput.builder()
        .algorithm(TokenSigningAlgorithm.ECDSA_256)
        .issuer("http://example.com/issuer")
        .issuerCredential(issuerCredential)
        .walletPublicKey(walletKey.toPublicKey())
        .expirationDuration(Duration.ofDays(1))
        .attributes(TestData.defaultPidUserAttributes)
        .build(), null);

    performTest("Bad algorithm",
      TokenInput.builder()
        .algorithm(TokenSigningAlgorithm.RSA_PSS_256)
        .issuer("http://example.com/issuer")
        .issuerCredential(issuerCredential)
        .walletPublicKey(walletKey.toPublicKey())
        .expirationDuration(Duration.ofDays(1))
        .attributes(TestData.defaultPidUserAttributes)
        .build(), TokenIssuingException.class);

    performTest("Null algorithm",
      TokenInput.builder()
        .issuer("http://example.com/issuer")
        .issuerCredential(issuerCredential)
        .walletPublicKey(walletKey.toPublicKey())
        .expirationDuration(Duration.ofDays(1))
        .attributes(TestData.defaultPidUserAttributes)
        .build(), TokenIssuingException.class);

    performTest("No wallet key",
      TokenInput.builder()
        .algorithm(TokenSigningAlgorithm.ECDSA_256)
        .issuer("http://example.com/issuer")
        .issuerCredential(issuerCredential)
        .expirationDuration(Duration.ofDays(1))
        .attributes(TestData.defaultPidUserAttributes)
        .build(), null);

    performTest("No expiration time",
      TokenInput.builder()
        .algorithm(TokenSigningAlgorithm.ECDSA_256)
        .issuer("http://example.com/issuer")
        .issuerCredential(issuerCredential)
        .walletPublicKey(walletKey.toPublicKey())
        .attributes(TestData.defaultPidUserAttributes)
        .build(), TokenIssuingException.class);
  }

  void performTest(String description, TokenInput tokenInput, Class<? extends Exception> exceptionClass) throws Exception {
    log.info("TEST CASE:\n================\n{}\n================", description);
    MdlTokenIssuer tokenIssuer = new MdlTokenIssuer(false);
    if (exceptionClass != null) {
      Exception exception = Assertions.assertThrows(exceptionClass, () -> {
        tokenIssuer.issueToken(tokenInput);
        Assertions.fail("Expected exception not thrown");
      });
      log.info("Thrown expected exception: {} - {}", exception.getClass().getSimpleName(), exception.getMessage());
      log.info("Cause: {} - {}", exception.getCause().getClass().getSimpleName(), exception.getCause().toString());
    } else {
      byte[] issuedToken = tokenIssuer.issueToken(tokenInput);
      List<TrustedKey> trustedKeys = List.of(TrustedKey.builder()
        .certificate(tokenInput.getIssuerCredential().getCertificate())
        .build());
      MdlIssuerSignedValidator tokenValidator = new MdlIssuerSignedValidator();
      MdlIssuerSignedValidationResult validationResult = tokenValidator.validateToken(issuedToken, trustedKeys);
      log.info("Token validated OK");
      logIssuerSignedToken(issuedToken, validationResult.getMso());
    }

  }

  public static void logIssuerSignedToken(byte[] issuedToken, MobileSecurityObject mso) throws Exception {
    log.info("Token CBOR:\n{}", Hex.toHexString(issuedToken));
    IssuerSigned issuerSigned = IssuerSigned.deserialize(issuedToken);
    issuerSigned.getNameSpaces().forEach((ns, v) -> {
      List<String> attributeValPrints = new ArrayList<>();
      v.forEach(issuerSignedItem -> {
        try {
          attributeValPrints.add(CBORUtils.cborToPrettyJson(
          CBORUtils.CBOR_MAPPER.writeValueAsBytes(issuerSignedItem)));
        } catch (IOException e) {
          throw new RuntimeException(e);
        }
      });
      log.info("Name space: {}\n{}", ns, String.join("\n", attributeValPrints));
    });
    log.info("Mobile security object:\n{}", CBORUtils.cborToPrettyJson(CBORUtils.CBOR_MAPPER.writeValueAsBytes(mso)));
  }



}

// SPDX-FileCopyrightText: 2024 diggsweden/eudiw-wallet-token-lib
//
// SPDX-License-Identifier: EUPL-1.2

package se.digg.wallet.datatypes.sdjwt.process;

import com.nimbusds.jose.JOSEObjectType;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jwt.SignedJWT;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.time.Duration;
import java.util.List;
import java.util.Map;
import java.util.Random;
import lombok.extern.slf4j.Slf4j;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import se.digg.cose.AlgorithmID;
import se.digg.cose.COSEKey;
import se.digg.wallet.datatypes.common.TestCredentials;
import se.digg.wallet.datatypes.common.TestData;
import se.digg.wallet.datatypes.common.TokenAttribute;
import se.digg.wallet.datatypes.common.TokenAttributeType;
import se.digg.wallet.datatypes.common.TokenDigestAlgorithm;
import se.digg.wallet.datatypes.common.TokenIssuingException;
import se.digg.wallet.datatypes.common.TokenSigningAlgorithm;
import se.digg.wallet.datatypes.common.TrustedKey;
import se.digg.wallet.datatypes.sdjwt.JSONUtils;
import se.digg.wallet.datatypes.sdjwt.data.ClaimsWithDisclosure;
import se.digg.wallet.datatypes.sdjwt.data.Disclosure;
import se.digg.wallet.datatypes.sdjwt.data.SdJwt;
import se.swedenconnect.security.credential.PkiCredential;

@Slf4j
class SdJwtTokenIssuerTest {

  public static final Random RNG = new SecureRandom();

  static PkiCredential issuerCredential;
  static ECKey walletKey;
  static SdJwtTokenIssuer tokenIssuer;
  static SdJwtTokenIssuer legacyTokenIssuer;
  static SdJwtTokenIssuer kidTokenIssuer;

  @BeforeAll
  static void setUp() {
    issuerCredential = TestCredentials.p256_issuerCredential;
    walletKey = TestCredentials.p256_walletKey;
    tokenIssuer = new SdJwtTokenIssuer();
    legacyTokenIssuer = new SdJwtTokenIssuer();
    legacyTokenIssuer.setLegacySdJwtHeaderType(true);
    kidTokenIssuer = new SdJwtTokenIssuer();
    kidTokenIssuer.setIncludeKid(true);
  }

  @Test
  void basicTest() throws Exception {
    SdJwtTokenInput tokenInput = SdJwtTokenInput.sdJwtINputBuilder()
        .algorithm(TokenSigningAlgorithm.ECDSA_256)
        .issuer("http://example.com/issuer")
        .issuerCredential(issuerCredential)
        .walletPublicKey(walletKey.toPublicKey())
        .expirationDuration(Duration.ofDays(1))
        .attributes(TestData.defaultPidUserAttributes)
        .build();
    String token = new String(
        tokenIssuer.issueToken(tokenInput),
        StandardCharsets.UTF_8);
    logToken(
        token,
        tokenInput.getAlgorithm().getDigestAlgorithm().getJdkName());
  }

  @Test
  void testCases() throws Exception {
    performTest(
        "Default EC issuer key setup",
        SdJwtTokenInput.sdJwtINputBuilder()
            .algorithm(TokenSigningAlgorithm.ECDSA_256)
            .issuer("http://example.com/issuer")
            .issuerCredential(issuerCredential)
            .walletPublicKey(walletKey.toPublicKey())
            .expirationDuration(Duration.ofDays(1))
            .attributes(TestData.defaultPidUserAttributes)
            .build(),
        tokenIssuer,
        null);

    performTest(
        "Issue token with kid in header",
        SdJwtTokenInput.sdJwtINputBuilder()
            .algorithm(TokenSigningAlgorithm.ECDSA_256)
            .issuer("http://example.com/issuer")
            .issuerCredential(issuerCredential)
            .walletPublicKey(walletKey.toPublicKey())
            .expirationDuration(Duration.ofDays(1))
            .attributes(TestData.defaultPidUserAttributes)
            .build(),
        kidTokenIssuer,
        null);

    performTest(
        "RSA Issuer key",
        SdJwtTokenInput.sdJwtINputBuilder()
            .algorithm(TokenSigningAlgorithm.RSA_PSS_512)
            .issuer("http://example.com/issuer")
            .issuerCredential(TestCredentials.rsa_issuerCredential)
            .walletPublicKey(walletKey.toPublicKey())
            .expirationDuration(Duration.ofDays(1))
            .attributes(TestData.defaultPidUserAttributes)
            .build(),
        tokenIssuer,
        null);

    performTest(
        "Legacy SD-JWT type",
        SdJwtTokenInput.sdJwtINputBuilder()
            .algorithm(TokenSigningAlgorithm.ECDSA_256)
            .issuer("http://example.com/issuer")
            .issuerCredential(issuerCredential)
            .walletPublicKey(walletKey.toPublicKey())
            .expirationDuration(Duration.ofDays(1))
            .attributes(TestData.defaultPidUserAttributes)
            .build(),
        legacyTokenIssuer,
        null);

    performTest(
        "Bad algorithm",
        SdJwtTokenInput.sdJwtINputBuilder()
            .algorithm(TokenSigningAlgorithm.RSA_PSS_256)
            .issuer("http://example.com/issuer")
            .issuerCredential(issuerCredential)
            .walletPublicKey(walletKey.toPublicKey())
            .expirationDuration(Duration.ofDays(1))
            .attributes(TestData.defaultPidUserAttributes)
            .build(),
        legacyTokenIssuer,
        TokenIssuingException.class);

    performTest(
        "Null algorithm",
        SdJwtTokenInput.sdJwtINputBuilder()
            .issuer("http://example.com/issuer")
            .issuerCredential(issuerCredential)
            .walletPublicKey(walletKey.toPublicKey())
            .expirationDuration(Duration.ofDays(1))
            .attributes(TestData.defaultPidUserAttributes)
            .build(),
        legacyTokenIssuer,
        TokenIssuingException.class);

    performTest(
        "Null issuer",
        SdJwtTokenInput.sdJwtINputBuilder()
            .algorithm(TokenSigningAlgorithm.ECDSA_256)
            .issuerCredential(issuerCredential)
            .walletPublicKey(walletKey.toPublicKey())
            .expirationDuration(Duration.ofDays(1))
            .attributes(TestData.defaultPidUserAttributes)
            .build(),
        legacyTokenIssuer,
        TokenIssuingException.class);

    performTest(
        "No wallet key",
        SdJwtTokenInput.sdJwtINputBuilder()
            .algorithm(TokenSigningAlgorithm.ECDSA_256)
            .issuer("http://example.com/issuer")
            .issuerCredential(issuerCredential)
            .expirationDuration(Duration.ofDays(1))
            .attributes(TestData.defaultPidUserAttributes)
            .build(),
        tokenIssuer,
        TokenIssuingException.class);

    performTest(
        "No expiration time",
        SdJwtTokenInput.sdJwtINputBuilder()
            .algorithm(TokenSigningAlgorithm.ECDSA_256)
            .issuer("http://example.com/issuer")
            .issuerCredential(issuerCredential)
            .walletPublicKey(walletKey.toPublicKey())
            .attributes(TestData.defaultPidUserAttributes)
            .build(),
        tokenIssuer,
        TokenIssuingException.class);


  }

  /**
   * Performs a test of the SdJwtTokenIssuer's functionality using the provided inputs.
   *
   * @param description a description of the test case for logging purposes
   * @param tokenInput the input data for the token to be issued
   * @param tokenIssuer the token issuer used to issue the token
   * @param exceptionClass the class of the expected exception to be thrown during the test, or null
   *        if no exception is expected
   * @throws Exception if an unexpected error occurs during the test execution
   */
  void performTest(
      String description,
      SdJwtTokenInput tokenInput,
      SdJwtTokenIssuer tokenIssuer,
      Class<? extends Exception> exceptionClass) throws Exception {
    log.info("TEST CASE:\n================\n{}\n================", description);
    if (exceptionClass != null) {
      Exception exception = Assertions.assertThrows(exceptionClass, () -> {
        tokenIssuer.issueToken(tokenInput);
        Assertions.fail("Expected exception not thrown");
      });
      log.info(
          "Thrown expected exception: {} - {}",
          exception.getClass().getSimpleName(),
          exception.getMessage());
      log.info(
          "Cause: {} - {}",
          exception.getCause().getClass().getSimpleName(),
          exception.getCause().toString());
    } else {
      byte[] issuedToken = tokenIssuer.issueToken(tokenInput);
      List<TrustedKey> trustedKeys = List.of(
          TrustedKey.builder()
              .certificate(tokenInput.getIssuerCredential().getCertificate())
              .build());
      SdJwtTokenValidator tokenValidator = new SdJwtTokenValidator();
      SdJwtTokenValidationResult validationResult =
          tokenValidator.validateToken(issuedToken, trustedKeys);
      log.info("Token validated OK");
      logToken(
          new String(issuedToken, StandardCharsets.UTF_8),
          tokenInput.getAlgorithm().getDigestAlgorithm().getJdkName());
      JOSEObjectType type = validationResult
          .getVcToken()
          .getIssuerSigned()
          .getHeader()
          .getType();
      if (tokenIssuer.isLegacySdJwtHeaderType()) {
        Assertions.assertEquals(SdJwt.SD_JWT_TYPE_LEGACY, type);
      } else {
        Assertions.assertEquals(SdJwt.SD_JWT_TYPE, type);
      }
      String kid = validationResult
          .getVcToken()
          .getIssuerSigned()
          .getHeader()
          .getKeyID();
      if (tokenIssuer.isIncludeKid()) {
        Assertions.assertNotNull(kid);
      } else {
        Assertions.assertNull(kid);
      }
    }
  }

  @Test
  void dynamicClaimsTest() throws Exception {
    TokenSigningAlgorithm algorithm = TokenSigningAlgorithm.ECDSA_256;
    TokenDigestAlgorithm digestAlgorithm = algorithm.getDigestAlgorithm();
    SdJwtTokenInput tokenInput = SdJwtTokenInput.sdJwtINputBuilder()
        .issuer("http://example.com/issuer")
        .issuerCredential(issuerCredential)
        .algorithm(algorithm)
        .expirationDuration(Duration.ofDays(1))
        .walletPublicKey(COSEKey.generateKey(AlgorithmID.ECDSA_256).AsPublicKey())
        .claimsWithDisclosure(
            ClaimsWithDisclosure.builder(digestAlgorithm)
                .openClaim("open_claim", "claim-value")
                .disclosure(
                    new Disclosure(
                        TokenAttribute.builder()
                            .type(new TokenAttributeType("given_name"))
                            .value("John")
                            .build()))
                .disclosure(
                    new Disclosure(
                        TokenAttribute.builder()
                            .type(new TokenAttributeType("Surname"))
                            .value("Doe")
                            .build()))
                .build())
        .build();
    SdJwtTokenIssuer tokenIssuer = new SdJwtTokenIssuer();
    tokenIssuer.setLegacySdJwtHeaderType(true);
    String token = new String(
        tokenIssuer.issueToken(tokenInput),
        StandardCharsets.UTF_8);
    logToken(token, digestAlgorithm.getJdkName());
  }

  /**
   * Method to test the issuance of a credential token and perform selective disclosure.
   *
   * @throws Exception if an error occurs during the test execution
   */
  @Test
  void fullIssueAndPresentationAndValidationTest() throws Exception {
    // Pick key and algorithms
    TokenSigningAlgorithm ecdsa256 = TokenSigningAlgorithm.ECDSA_256;
    COSEKey walletKeyPair = COSEKey.generateKey(ecdsa256.getAlgorithmID());
    // Define token input
    SdJwtTokenInput tokenInput = SdJwtTokenInput.sdJwtINputBuilder()
        .issuer("http://example.com/issuer")
        .issuerCredential(issuerCredential)
        .algorithm(ecdsa256)
        .expirationDuration(Duration.ofDays(1))
        .walletPublicKey(walletKeyPair.AsPublicKey())
        .attributes(TestData.defaultPidUserAttributes)
        .build();
    // Create token issuer
    SdJwtTokenIssuer tokenIssuer = new SdJwtTokenIssuer();
    // Issue token
    String token = new String(
        tokenIssuer.issueToken(tokenInput),
        StandardCharsets.UTF_8);
    // Log issued token
    logToken(token, ecdsa256.getDigestAlgorithm().getJdkName());

    // Selective disclosure in wallet
    List<String> disclosedAttributes = List.of(
        "given_name",
        "birth_date",
        "family_name",
        "issuing_authority");
    SdJwt parsed = SdJwt.parse(token);
    // Get all available disclosures
    List<Disclosure> allDisclosures = parsed.getDisclosures();
    // Reduce the list of disclosures
    /*
     * List<String> userDisclosures = filterDisclosure( allDisclosures, disclosedAttributes // Get
     * the reduced list to sign String unprotectedPresentation = parsed.unprotectedPresentation(
     * disclosedAttributes ); );
     */
    // Sign the reduced disclosures with the wallet private key
    String protectededPresentation = parsed.protectedPresentation(
        ecdsa256.jwsSigner(walletKeyPair.AsPrivateKey()),
        ecdsa256.getJwsAlgorithm(),
        "http://example.com/aud",
        JSONUtils.base64URLString(
            new BigInteger(128, RNG).negate().toByteArray()),
        disclosedAttributes);
    // Log result
    logToken(
        protectededPresentation,
        ecdsa256.getDigestAlgorithm().getJdkName());

    // Check that token validates OK
    SdJwtTokenValidator tokenValidator = new SdJwtTokenValidator();
    SdJwtTokenValidationResult validationResult = tokenValidator.validateToken(
        protectededPresentation.getBytes(StandardCharsets.UTF_8),
        null);

    log.info(
        "Reconstructed discolsed token payload:\n{}",
        JSONUtils.JSON_MAPPER.writerWithDefaultPrettyPrinter()
            .writeValueAsString(
                validationResult.getDisclosedTokenPayload().toJSONObject()));

    Map<String, Object> disclosedAttrMap = validationResult
        .getDisclosedTokenPayload()
        .toJSONObject();
    for (String attributeName : disclosedAttributes) {
      Assertions.assertTrue(disclosedAttrMap.containsKey(attributeName));
      Assertions.assertNotNull(disclosedAttrMap.get(attributeName));
      log.info(
          "Disclosed attribute: {} = {}",
          attributeName,
          disclosedAttrMap.get(attributeName));
    }

    List<String> excludedDisclosures = allDisclosures
        .stream()
        .filter(disclosure -> !disclosedAttributes.contains(disclosure.getName()))
        .map(Disclosure::getName)
        .toList();
    for (String excludedDisclosure : excludedDisclosures) {
      Assertions.assertFalse(disclosedAttrMap.containsKey(excludedDisclosure));
      log.info("Non disclosed attribute: {}", excludedDisclosure);
    }
  }

  public static void logToken(String token, String digestAlgo)
      throws Exception {
    log.info("Issued sdJwt token: \n{}", token);

    String[] split = token.split("~");
    log.info(
        "Token header:\n{}",
        JSONUtils.JSON_MAPPER.writerWithDefaultPrettyPrinter()
            .writeValueAsString(
                SignedJWT.parse(split[0]).getHeader().toJSONObject()));
    log.info(
        "Token payload:\n{}",
        JSONUtils.JSON_MAPPER.writerWithDefaultPrettyPrinter()
            .writeValueAsString(
                SignedJWT.parse(split[0]).getJWTClaimsSet().getClaims()));
    log.info("Disclosures: ");

    int end = token.endsWith("~") ? split.length : split.length - 1;

    for (int i = 1; i < end; i++) {
      String disclosureB64 = split[i];
      Disclosure disclosure = new Disclosure(disclosureB64);
      log.info(
          "Disclosure hash: {}",
          JSONUtils.base64URLString(
              JSONUtils.disclosureHash(disclosure, digestAlgo)));
      log.info("Disclosure str: {}", disclosureB64);
      log.info("Disclosure: {}", disclosure.getDisclosure());
    }

    if (!token.endsWith("~")) {
      SignedJWT cnfJwt = SignedJWT.parse(split[split.length - 1]);
      log.info(
          "Token header:\n{}",
          JSONUtils.JSON_MAPPER.writerWithDefaultPrettyPrinter()
              .writeValueAsString(cnfJwt.getHeader().toJSONObject()));
      log.info(
          "Token payload:\n{}",
          JSONUtils.JSON_MAPPER.writerWithDefaultPrettyPrinter()
              .writeValueAsString(cnfJwt.getJWTClaimsSet().getClaims()));
    }
  }
}

package se.digg.wallet.datatypes.sdjwt.process;

import lombok.extern.slf4j.Slf4j;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import se.digg.wallet.datatypes.common.*;
import se.digg.wallet.datatypes.sdjwt.JSONUtils;
import se.swedenconnect.security.credential.PkiCredential;

import java.security.PublicKey;
import java.time.Duration;
import java.time.Instant;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

@Slf4j
class SdJwtTokenValidatorTest {

  static SdJwtTokenIssuer tokenIssuer;

  @BeforeAll
  static void setUp() {
    tokenIssuer = new SdJwtTokenIssuer();
  }

  @Test
  void testCases() throws Exception {
    SdJwtTokenValidator defaultValidator = new SdJwtTokenValidator();
    byte[] ecToken = getToken(tokenIssuer, TestCredentials.p256_issuerCredential, false, TestCredentials.p256_walletKey.toPublicKey());
    byte[] ecTokenLegacy = getToken(tokenIssuer, TestCredentials.p256_issuerCredential, true, TestCredentials.p256_walletKey.toPublicKey());
    byte[] rsaToken = getToken(tokenIssuer, TestCredentials.rsa_issuerCredential, false, TestCredentials.p256_walletKey.toPublicKey());
    List<TrustedKey> allTrusted = List.of(
      TrustedKey.builder().certificate(TestCredentials.p256_issuerCredential.getCertificate()).build(),
      TrustedKey.builder().certificate(TestCredentials.rsa_issuerCredential.getCertificate()).build()
    );
    List<TrustedKey> rsaTrusted = List.of(
      TrustedKey.builder().certificate(TestCredentials.rsa_issuerCredential.getCertificate()).build()
    );

    // Default test case
    assertTrue(performTestCase(
      "Default test case",
      defaultValidator, ecToken, allTrusted,
      null).getValidationCertificate().equals(TestCredentials.p256_issuerCredential.getCertificate()));
    assertTrue(performTestCase(
      "No trusted keys",
      defaultValidator, ecToken, null,
      null).getValidationCertificate().equals(TestCredentials.p256_issuerCredential.getCertificate()));
    assertTrue(performTestCase(
      "RSA test case",
      defaultValidator, rsaToken, allTrusted,
      null).getValidationCertificate().equals(TestCredentials.rsa_issuerCredential.getCertificate()));
    performTestCase(
      "Legacy SD-JWT type",
      defaultValidator, ecTokenLegacy, allTrusted,
      null);
    performTestCase(
      "Untrusted key",
      defaultValidator, ecTokenLegacy, rsaTrusted,
      TokenValidationException.class);
  }

  public static byte[] getToken(SdJwtTokenIssuer tokenIssuer, PkiCredential issuerCredential, boolean legacyType,
                                PublicKey walletPublic) throws Exception {
    tokenIssuer.setLegacySdJwtHeaderType(legacyType);
    TokenSigningAlgorithm algorithm = issuerCredential.getPublicKey() instanceof java.security.interfaces.ECPublicKey
      ? TokenSigningAlgorithm.ECDSA_256
      : TokenSigningAlgorithm.RSA_PSS_256;

    return tokenIssuer.issueToken(SdJwtTokenInput.sdJwtINputBuilder()
      .algorithm(algorithm)
      .issuer("http://example.com/issuer")
      .issuerCredential(issuerCredential)
      .walletPublicKey(walletPublic)
      .expirationDuration(Duration.ofDays(1))
      .attributes(TestData.defaultPidUserAttributes)
      .build());
  }

  SdJwtTokenValidationResult performTestCase(String description, SdJwtTokenValidator validator, byte[] token, List<TrustedKey> trustedKeys,
                       Class<? extends Exception> expectedException) throws Exception {
    log.info("TEST CASE:\n================\n{}\n================", description);
    
    if (expectedException != null) {
      Exception exception = assertThrows(expectedException, () -> {
        validator.validateToken(token, trustedKeys);
        fail("Expected exception not thrown");
      });
      log.info("Thrown expected exception: {} - {}", exception.getClass().getSimpleName(), exception.getMessage());
      if (exception.getCause() != null){
        log.info("Cause: {} - {}", exception.getCause().getClass().getSimpleName(), exception.getCause().toString());
      }
    } else {
      SdJwtTokenValidationResult validationResult = validator.validateToken(token, trustedKeys);
      logValidationResult(validationResult);
      assertNotNull(validationResult);
      assertNotNull(validationResult.getValidationCertificate());
      assertNotNull(validationResult.getValidationKey());
      assertNotNull(validationResult.getVcToken());
      assertNotNull(validationResult.getDisclosedTokenPayload());
      assertNull(validationResult.getAudience());
      assertTrue(validationResult.getIssueTime().isBefore(Instant.now()));
      assertTrue(validationResult.getExpirationTime().isAfter(validationResult.getIssueTime()));
      assertTrue(validationResult.getExpirationTime().isAfter(Instant.now()));
      return validationResult;
    }
    return null;
  }

  public static void logValidationResult(SdJwtTokenValidationResult validationResult) throws Exception {
    log.info("Validation Certificate: {}", validationResult.getValidationCertificate());
    log.info("Validation Key: {}", validationResult.getValidationKey());
    log.info("VC Token: {}", validationResult.getVcToken().getIssuerSigned().serialize().replace("\n", "\\n"));
    log.info("Disclosed Token Payload: {}", JSONUtils.JSON_MAPPER.writerWithDefaultPrettyPrinter().writeValueAsString(validationResult.getDisclosedTokenPayload().toJSONObject()));
    log.info("Audience: {}", validationResult.getAudience());
    log.info("Issue Time: {}", validationResult.getIssueTime());
    log.info("Expiration Time: {}", validationResult.getExpirationTime());
    log.info("Request nonce: {}", validationResult.getPresentationRequestNonce());
  }

}
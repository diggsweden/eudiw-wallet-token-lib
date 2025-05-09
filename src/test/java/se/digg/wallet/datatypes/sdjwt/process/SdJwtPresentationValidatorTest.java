// SPDX-FileCopyrightText: 2025 diggsweden/eudiw-wallet-token-lib
//
// SPDX-License-Identifier: EUPL-1.2

package se.digg.wallet.datatypes.sdjwt.process;

import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.fail;

import java.security.PrivateKey;
import java.security.PublicKey;
import java.time.Duration;
import java.util.List;
import lombok.extern.slf4j.Slf4j;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import se.digg.wallet.datatypes.common.TestCredentials;
import se.digg.wallet.datatypes.common.TestData;
import se.digg.wallet.datatypes.common.TokenSigningAlgorithm;
import se.digg.wallet.datatypes.common.TokenValidationException;
import se.digg.wallet.datatypes.common.TrustedKey;
import se.digg.wallet.datatypes.sdjwt.data.SdJwtPresentationInput;
import se.digg.wallet.datatypes.sdjwt.data.SdJwtPresentationValidationInput;

@Slf4j
class SdJwtPresentationValidatorTest {

  static SdJwtTokenIssuer tokenIssuer;

  static SdJwtTokenPresenter tokenPresenter;

  @BeforeAll
  static void setUp() {
    tokenIssuer = new SdJwtTokenIssuer();
    tokenPresenter = new SdJwtTokenPresenter();
  }

  @Test
  void testCases() throws Exception {
    PublicKey walletPublic = TestCredentials.p256_walletKey.toPublicKey();
    PrivateKey walletPrivate = TestCredentials.p256_walletKey.toPrivateKey();

    byte[] ecToken = SdJwtTokenValidatorTest.getToken(
        tokenIssuer,
        TestCredentials.p256_issuerCredential,
        false,
        walletPublic);
    byte[] rsaToken = SdJwtTokenValidatorTest.getToken(
        tokenIssuer,
        TestCredentials.rsa_issuerCredential,
        false,
        walletPublic);

    List<TrustedKey> allTrusted = List.of(
        TrustedKey.builder()
            .certificate(TestCredentials.p256_issuerCredential.getCertificate())
            .build(),
        TrustedKey.builder()
            .certificate(TestCredentials.rsa_issuerCredential.getCertificate())
            .build());
    List<TrustedKey> rsaTrusted = List.of(
        TrustedKey.builder()
            .certificate(TestCredentials.rsa_issuerCredential.getCertificate())
            .build());
    List<String> allDisclosure = List.of(
        "issuance_date",
        "issuing_country",
        "given_name",
        "age_over_18",
        "birth_date",
        "expiry_date",
        "family_name",
        "issuing_authority");
    List<String> nameDisclosure = List.of("given_name", "family_name");

    SdJwtPresentationInput presentationInput = SdJwtPresentationInput.builder()
        .token(ecToken)
        .audience("https://example.com/audience")
        .nonce("abcdefgh1234567890")
        .algorithm(TokenSigningAlgorithm.ECDSA_256)
        .disclosures(nameDisclosure)
        .build();

    SdJwtPresentationInput rsaPresentationInput = SdJwtPresentationInput.builder()
        .token(rsaToken)
        .audience("https://example.com/audience")
        .nonce("abcdefgh1234567890")
        .algorithm(TokenSigningAlgorithm.ECDSA_256)
        .disclosures(allDisclosure)
        .build();

    SdJwtPresentationValidationInput validationInput = new SdJwtPresentationValidationInput(
        "abcdefgh1234567890",
        "https://example.com/audience");
    SdJwtPresentationValidationInput wrongNonceInput = new SdJwtPresentationValidationInput(
        "abcdefgh123456789",
        "https://example.com/audience");
    SdJwtPresentationValidationInput wrongAudienceInput = new SdJwtPresentationValidationInput(
        "abcdefgh1234567890",
        "https://example.com/wrong-audience");

    byte[] presentedToken = tokenPresenter.presentToken(
        presentationInput,
        walletPrivate);
    byte[] rsaPresentedToken = tokenPresenter.presentToken(
        rsaPresentationInput,
        walletPrivate);

    SdJwtPresentationValidator defaultValidator = new SdJwtPresentationValidator();

    performTestCase(
        "Default EC test case",
        defaultValidator,
        validationInput,
        presentedToken,
        allTrusted,
        null);
    performTestCase(
        "RSA test case",
        defaultValidator,
        validationInput,
        rsaPresentedToken,
        rsaTrusted,
        null);
    performTestCase(
        "Wrong nonce test case",
        defaultValidator,
        wrongNonceInput,
        presentedToken,
        allTrusted,
        TokenValidationException.class);
    performTestCase(
        "Wrong audience test case",
        defaultValidator,
        wrongAudienceInput,
        presentedToken,
        allTrusted,
        TokenValidationException.class);

    // Ref implementation test
    SdJwtPresentationValidationInput refValidationInput = new SdJwtPresentationValidationInput(
        TestData.SD_JWT_EUDI_REF_01_NONCE,
        TestData.SD_JWT_EUDI_REF_01_AUDIENCE);

    // Set time skew to make sure this never expires
    SdJwtPresentationValidator refValidator = new SdJwtPresentationValidator(
        Duration.ofDays(36500));
    performTestCase(
        "Reference implementation test",
        refValidator,
        refValidationInput,
        TestData.SD_JWT_EUDI_REF_01.getBytes(),
        null,
        null);
  }

  void performTestCase(
      String description,
      SdJwtPresentationValidator validator,
      SdJwtPresentationValidationInput input,
      byte[] presentation,
      List<TrustedKey> trustedKeys,
      Class<? extends Exception> expectedException) throws Exception {
    log.info("TEST CASE:\n================\n{}\n================", description);

    if (expectedException != null) {
      Exception exception = assertThrows(expectedException, () -> {
        validator.validatePresentation(presentation, input, trustedKeys);
        fail("Expected exception not thrown");
      });
      log.info(
          "Thrown expected exception: {} - {}",
          exception.getClass().getSimpleName(),
          exception.getMessage());
      if (exception.getCause() != null) {
        log.info(
            "Cause: {} - {}",
            exception.getCause().getClass().getSimpleName(),
            exception.getCause().getMessage());
      }
    } else {
      SdJwtTokenValidationResult validationResult = validator.validatePresentation(presentation,
          input,
          trustedKeys);
      assertNotNull(validationResult);
      SdJwtTokenValidatorTest.logValidationResult(validationResult);
      log.info(
          "Disclosed attributes:\n{}",
          String.join(
              "\n",
              validationResult
                  .getDisclosedAttributes()
                  .entrySet()
                  .stream()
                  .map(e -> e.getKey() + " -> " + e.getValue())
                  .toList()));
      assertNotNull(validationResult.getValidationCertificate());
      assertNotNull(validationResult.getValidationKey());
      assertNotNull(validationResult.getVcToken());
      assertNotNull(validationResult.getDisclosedTokenPayload());
      assertNotNull(validationResult.getAudience());
    }
  }
}

package se.digg.wallet.datatypes.sdjwt.process;

import lombok.extern.slf4j.Slf4j;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import se.digg.wallet.datatypes.common.TestCredentials;
import se.digg.wallet.datatypes.common.TokenSigningAlgorithm;
import se.digg.wallet.datatypes.common.TokenValidationException;
import se.digg.wallet.datatypes.common.TrustedKey;
import se.digg.wallet.datatypes.sdjwt.data.SdJwtPresentationInput;
import se.digg.wallet.datatypes.sdjwt.data.SdJwtPresentationValidationInput;

import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

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

    byte[] ecToken = SdJwtTokenValidatorTest.getToken(tokenIssuer, TestCredentials.p256_issuerCredential, false, walletPublic);
    byte[] rsaToken = SdJwtTokenValidatorTest.getToken(tokenIssuer, TestCredentials.rsa_issuerCredential, false, walletPublic);

    List<TrustedKey> allTrusted = List.of(
      TrustedKey.builder().certificate(TestCredentials.p256_issuerCredential.getCertificate()).build(),
      TrustedKey.builder().certificate(TestCredentials.rsa_issuerCredential.getCertificate()).build()
    );
    List<TrustedKey> rsaTrusted = List.of(
      TrustedKey.builder().certificate(TestCredentials.rsa_issuerCredential.getCertificate()).build()
    );
    List<String> allDisclosure = List.of("issuance_date", "issuing_country", "given_name", "age_over_18", "birth_date", "expiry_date", "family_name", "issuing_authority");
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
      "abcdefgh1234567890", "https://example.com/audience"
    );
    SdJwtPresentationValidationInput wrongNonceInput = new SdJwtPresentationValidationInput(
      "abcdefgh123456789", "https://example.com/audience"
    );
    SdJwtPresentationValidationInput wrongAudienceInput = new SdJwtPresentationValidationInput(
      "abcdefgh1234567890", "https://example.com/wrong-audience"
    );

    byte[] presentedToken = tokenPresenter.presentToken(presentationInput, walletPrivate);
    byte[] rsaPresentedToken = tokenPresenter.presentToken(rsaPresentationInput, walletPrivate);

    SdJwtPresentationValidator defaultValidator = new SdJwtPresentationValidator();

    performTestCase(
      "Default EC test case",
      defaultValidator,
      validationInput,
      presentedToken,
      allTrusted, null);
    performTestCase(
      "RSA test case",
      defaultValidator,
      validationInput,
      rsaPresentedToken,
      rsaTrusted, null);
    performTestCase(
      "Wrong nonce test case",
      defaultValidator,
      wrongNonceInput,
      presentedToken,
      allTrusted, TokenValidationException.class);
    performTestCase(
      "Wrong audience test case",
      defaultValidator,
      wrongAudienceInput,
      presentedToken,
      allTrusted, TokenValidationException.class);
  }


  void performTestCase(String description, SdJwtPresentationValidator validator, SdJwtPresentationValidationInput input,
       byte[] presentation, List<TrustedKey> trustedKeys, Class<? extends Exception> expectedException) throws Exception {

    log.info("TEST CASE:\n================\n{}\n================", description);

    if (expectedException != null) {
      Exception exception = assertThrows(expectedException, () -> {
        validator.validatePresentation(presentation, input, trustedKeys);
        fail("Expected exception not thrown");
      });
      log.info("Thrown expected exception: {} - {}", exception.getClass().getSimpleName(), exception.getMessage());
      if (exception.getCause() != null) {
        log.info("Cause: {} - {}", exception.getCause().getClass().getSimpleName(), exception.getCause().getMessage());
      }
    } else {
      SdJwtTokenValidationResult validationResult = validator.validatePresentation(presentation, input, trustedKeys);
      assertNotNull(validationResult);
      SdJwtTokenValidatorTest.logValidationResult(validationResult);
      assertNotNull(validationResult.getValidationCertificate());
      assertNotNull(validationResult.getValidationKey());
      assertNotNull(validationResult.getVcToken());
      assertNotNull(validationResult.getDisclosedTokenPayload());
      assertNotNull(validationResult.getAudience());
    }

  }

}
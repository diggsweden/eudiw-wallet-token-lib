package se.digg.wallet.datatypes.sdjwt.process;

import lombok.extern.slf4j.Slf4j;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import se.digg.wallet.datatypes.common.TestCredentials;
import se.digg.wallet.datatypes.common.TokenPresentationException;
import se.digg.wallet.datatypes.common.TokenSigningAlgorithm;
import se.digg.wallet.datatypes.sdjwt.data.SdJwtPresentationInput;

import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

@Slf4j
class SdJwtTokenPresenterTest {

  static SdJwtTokenIssuer tokenIssuer;

  @BeforeAll
  static void setUp() {
    tokenIssuer = new SdJwtTokenIssuer();
  }

  @Test
  void testCases() throws Exception {

    SdJwtTokenPresenter defaultPresenter = new SdJwtTokenPresenter();
    PublicKey walletPublic = TestCredentials.p256_walletKey.toPublicKey();
    PublicKey rsaWalletPublic = TestCredentials.rsa_walletKey.toPublicKey();
    PrivateKey walletPrivate = TestCredentials.p256_walletKey.toPrivateKey();
    PrivateKey rsaWalletPrivate = TestCredentials.rsa_walletKey.toPrivateKey();

    byte[] ecToken = SdJwtTokenValidatorTest.getToken(tokenIssuer, TestCredentials.p256_issuerCredential, false, walletPublic);
    byte[] ecTokenRsaWallet = SdJwtTokenValidatorTest.getToken(tokenIssuer, TestCredentials.p256_issuerCredential, false, rsaWalletPublic);
    byte[] ecTokenLegacy = SdJwtTokenValidatorTest.getToken(tokenIssuer, TestCredentials.p256_issuerCredential, true, walletPublic);
    byte[] rsaToken = SdJwtTokenValidatorTest.getToken(tokenIssuer, TestCredentials.rsa_issuerCredential, false, walletPublic);

    List<String> allDisclosure = List.of("issuance_date", "issuing_country", "given_name", "age_over_18", "birth_date", "expiry_date", "family_name", "issuing_authority");
    List<String> nameDisclosure = List.of("given_name", "family_name");

    performTestCase("Default test case",
      defaultPresenter, SdJwtPresentationInput.builder()
        .token(ecToken)
        .audience("https://example.com/audience")
        .nonce("abcdefgh1234567890")
        .algorithm(TokenSigningAlgorithm.ECDSA_256)
        .disclosures(allDisclosure)
        .build(), walletPrivate,null);
    performTestCase("Legacy type declaration",
      defaultPresenter, SdJwtPresentationInput.builder()
        .token(ecTokenLegacy)
        .audience("https://example.com/audience")
        .nonce("abcdefgh1234567890")
        .algorithm(TokenSigningAlgorithm.ECDSA_256)
        .disclosures(allDisclosure)
        .build(), walletPrivate, null);
    performTestCase("RSA issuer key",
      defaultPresenter, SdJwtPresentationInput.builder()
        .token(rsaToken)
        .audience("https://example.com/audience")
        .nonce("abcdefgh1234567890")
        .algorithm(TokenSigningAlgorithm.ECDSA_256)
        .disclosures(nameDisclosure)
        .build(), walletPrivate, null);
    performTestCase("RSA wallet key",
      defaultPresenter, SdJwtPresentationInput.builder()
        .token(ecTokenRsaWallet)
        .audience("https://example.com/audience")
        .nonce("abcdefgh1234567890")
        .algorithm(TokenSigningAlgorithm.RSA_PSS_256)
        .disclosures(nameDisclosure)
        .build(), rsaWalletPrivate, null);
    performTestCase("Wrong wallet algorithm",
      defaultPresenter, SdJwtPresentationInput.builder()
        .token(ecTokenRsaWallet)
        .audience("https://example.com/audience")
        .nonce("abcdefgh1234567890")
        .algorithm(TokenSigningAlgorithm.ECDSA_256)
        .disclosures(nameDisclosure)
        .build(), rsaWalletPrivate, TokenPresentationException.class);
    performTestCase("No token",
      defaultPresenter, SdJwtPresentationInput.builder()
        .audience("https://example.com/audience")
        .nonce("abcdefgh1234567890")
        .algorithm(TokenSigningAlgorithm.ECDSA_256)
        .disclosures(allDisclosure)
        .build(), walletPrivate, TokenPresentationException.class);
    performTestCase("No audience",
      defaultPresenter, SdJwtPresentationInput.builder()
        .token(ecToken)
        .nonce("abcdefgh1234567890")
        .algorithm(TokenSigningAlgorithm.ECDSA_256)
        .disclosures(allDisclosure)
        .build(), walletPrivate, TokenPresentationException.class);
    performTestCase("No nonce",
      defaultPresenter, SdJwtPresentationInput.builder()
        .token(ecToken)
        .audience("https://example.com/audience")
        .algorithm(TokenSigningAlgorithm.ECDSA_256)
        .disclosures(allDisclosure)
        .build(), walletPrivate, TokenPresentationException.class);
    performTestCase("No algorithm",
      defaultPresenter, SdJwtPresentationInput.builder()
        .token(ecToken)
        .audience("https://example.com/audience")
        .nonce("abcdefgh1234567890")
        .disclosures(allDisclosure)
        .build(), walletPrivate, TokenPresentationException.class);
  }

  void performTestCase(String description, SdJwtTokenPresenter presenter, SdJwtPresentationInput input,
                       PrivateKey walletPrivate, Class<? extends Exception> expectedException) throws Exception {

    log.info("TEST CASE:\n================\n{}\n================", description);

    if (expectedException != null) {
      Exception exception = assertThrows(expectedException, () -> {
        presenter.presentToken(input, walletPrivate);
        fail("Expected exception not thrown");
      });
      log.info("Thrown expected exception: {} - {}", exception.getClass().getSimpleName(), exception.getMessage());
      if (exception.getCause() != null) {
        log.info("Cause: {} - {}", exception.getCause().getClass().getSimpleName(), exception.getCause().getMessage());
      }
    } else {
      byte[] presentedToken = presenter.presentToken(input, walletPrivate);
      SdJwtTokenIssuerTest.logToken(new String(presentedToken), input.getAlgorithm().getDigestAlgorithm().getJdkName());
      assertNotNull(presentedToken);
    }
  }
}
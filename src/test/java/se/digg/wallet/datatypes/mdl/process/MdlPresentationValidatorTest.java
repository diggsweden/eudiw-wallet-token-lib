// SPDX-FileCopyrightText: 2025 Digg - Agency for Digital Government
//
// SPDX-License-Identifier: EUPL-1.2

package se.digg.wallet.datatypes.mdl.process;

import static org.junit.jupiter.api.Assertions.*;

import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import lombok.extern.slf4j.Slf4j;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import se.digg.wallet.datatypes.common.TestCredentials;
import se.digg.wallet.datatypes.common.TokenAttributeNameSpace;
import se.digg.wallet.datatypes.common.TokenValidationException;
import se.digg.wallet.datatypes.common.TrustedKey;
import se.digg.wallet.datatypes.mdl.data.MdlPresentationInput;
import se.digg.wallet.datatypes.mdl.data.MdlPresentationValidationInput;

@Slf4j
class MdlPresentationValidatorTest {

  static MdlTokenIssuer tokenIssuer;

  static MdlTokenPresenter tokenPresenter;

  @BeforeAll
  static void setUp() {
    tokenIssuer = new MdlTokenIssuer();
    tokenPresenter = new MdlTokenPresenter();
  }

  @Test
  void testCases() throws Exception {
    PublicKey walletPublic = TestCredentials.p256_walletKey.toPublicKey();
    PrivateKey walletPrivate = TestCredentials.p256_walletKey.toPrivateKey();

    byte[] ecToken = MdlIssuerSignedValidatorTest.getToken(
      tokenIssuer,
      TestCredentials.p256_issuerCredential,
      walletPublic
    );
    byte[] rsaToken = MdlIssuerSignedValidatorTest.getToken(
      tokenIssuer,
      TestCredentials.rsa_issuerCredential,
      walletPublic
    );

    List<TrustedKey> allTrusted = List.of(
      TrustedKey.builder()
        .certificate(TestCredentials.p256_issuerCredential.getCertificate())
        .build(),
      TrustedKey.builder()
        .certificate(TestCredentials.rsa_issuerCredential.getCertificate())
        .build()
    );
    List<TrustedKey> rsaTrusted = List.of(
      TrustedKey.builder()
        .certificate(TestCredentials.rsa_issuerCredential.getCertificate())
        .build()
    );

    Collections.singletonMap(
      TokenAttributeNameSpace.EUDI_WALLET_PID.getId(),
      List.of(
        "issuance_date",
        "issuing_country",
        "given_name",
        "age_over_18",
        "birth_date",
        "expiry_date",
        "family_name",
        "issuing_authority"
      )
    );
    Map<String, List<String>> nameDisclosure = Collections.singletonMap(
      TokenAttributeNameSpace.EUDI_WALLET_PID.getId(),
      List.of("given_name", "family_name")
    );

    MdlPresentationInput presentationInput =
      MdlTokenPresenterTest.getInputBuilder(ecToken, nameDisclosure).build();
    MdlPresentationInput macPresentationInput =
      MdlTokenPresenterTest.getInputBuilder(ecToken, nameDisclosure)
        .clientPublicKey(TestCredentials.p256_clientKey.toPublicKey())
        .macDeviceAuthentication(true)
        .build();

    MdlPresentationInput rsaPresentationInput =
      MdlTokenPresenterTest.getInputBuilder(rsaToken, nameDisclosure).build();

    MdlPresentationValidationInput validationInput =
      new MdlPresentationValidationInput(presentationInput);
    MdlPresentationValidationInput macValidationInput =
      new MdlPresentationValidationInput(presentationInput);
    macValidationInput.setClientPrivateKey(TestCredentials.p256_clientKey.toPrivateKey());
    MdlPresentationValidationInput wrongNonceInput =
      new MdlPresentationValidationInput();
    wrongNonceInput.setClientId(presentationInput.getClientId());
    wrongNonceInput.setResponseUri(presentationInput.getResponseUri());
    wrongNonceInput.setMdocGeneratedNonce(
      presentationInput.getMdocGeneratedNonce()
    );
    wrongNonceInput.setRequestNonce("abcdefgh123456789");
    MdlPresentationValidationInput wrongAudienceInput =
      new MdlPresentationValidationInput();
    wrongAudienceInput.setClientId(presentationInput.getClientId());
    wrongAudienceInput.setResponseUri("https://example.com/wrong-audience");
    wrongAudienceInput.setMdocGeneratedNonce(
      presentationInput.getMdocGeneratedNonce()
    );
    wrongAudienceInput.setRequestNonce(presentationInput.getNonce());

    byte[] presentedToken = tokenPresenter.presentToken(
      presentationInput,
      walletPrivate
    );
    byte[] macPresentedToken = tokenPresenter.presentToken(
      macPresentationInput,
      walletPrivate
    );
    byte[] rsaPresentedToken = tokenPresenter.presentToken(
      rsaPresentationInput,
      walletPrivate
    );

    MdlPresentationValidator defaultValidator = new MdlPresentationValidator();

    performTestCase(
      "Default EC test case",
      defaultValidator,
      validationInput,
      presentedToken,
      allTrusted,
      null
    );
    performTestCase(
      "MAC test case",
      defaultValidator,
      macValidationInput,
      macPresentedToken,
      allTrusted,
      null
    );
    performTestCase(
      "RSA test case",
      defaultValidator,
      validationInput,
      rsaPresentedToken,
      rsaTrusted,
      null
    );
    performTestCase(
      "Wrong nonce test case",
      defaultValidator,
      wrongNonceInput,
      presentedToken,
      allTrusted,
      TokenValidationException.class
    );
    performTestCase(
      "Wrong audience test case",
      defaultValidator,
      wrongAudienceInput,
      presentedToken,
      allTrusted,
      TokenValidationException.class
    );
  }

  void performTestCase(
    String description,
    MdlPresentationValidator validator,
    MdlPresentationValidationInput input,
    byte[] presentation,
    List<TrustedKey> trustedKeys,
    Class<? extends Exception> expectedException
  ) throws Exception {
    log.info("TEST CASE:\n================\n{}\n================", description);

    if (expectedException != null) {
      Exception exception = assertThrows(expectedException, () -> {
        validator.validatePresentation(presentation, input, trustedKeys);
        fail("Expected exception not thrown");
      });
      log.info(
        "Thrown expected exception: {} - {}",
        exception.getClass().getSimpleName(),
        exception.getMessage()
      );
      if (exception.getCause() != null) {
        log.info(
          "Cause: {} - {}",
          exception.getCause().getClass().getSimpleName(),
          exception.getCause().getMessage()
        );
      }
    } else {
      MdlPresentationValidationResult validationResult =
        validator.validatePresentation(presentation, input, trustedKeys);
      assertNotNull(validationResult);
      MdlIssuerSignedValidatorTest.logValidationResult(validationResult);
      log.info(
        "Disclosed attributes:\n{}",
        String.join(
          "\n",
          validationResult
            .getDisclosedAttributes()
            .entrySet()
            .stream()
            .map(e -> e.getKey() + " -> " + e.getValue())
            .toList()
        )
      );
      assertNotNull(validationResult.getValidationCertificate());
      assertNotNull(validationResult.getValidationKey());
      assertNotNull(validationResult.getDocType());
      assertNotNull(validationResult.getVersion());
      assertNotNull(validationResult.getDisclosedAttributes());
      assertNotNull(validationResult.getExpirationTime());
      assertNotNull(validationResult.getMso());
      assertNotNull(validationResult.getIssuerSigned());
      assertNotNull(validationResult.getIssueTime());
    }
  }
}

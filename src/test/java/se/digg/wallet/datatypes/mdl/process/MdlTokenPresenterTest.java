// SPDX-FileCopyrightText: 2025 Digg - Agency for Digital Government
//
// SPDX-License-Identifier: EUPL-1.2

package se.digg.wallet.datatypes.mdl.process;

import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.fail;

import java.io.IOException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import lombok.extern.slf4j.Slf4j;
import org.bouncycastle.util.encoders.Hex;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import se.digg.wallet.datatypes.common.TestCredentials;
import se.digg.wallet.datatypes.common.TokenAttributeNameSpace;
import se.digg.wallet.datatypes.common.TokenPresentationException;
import se.digg.wallet.datatypes.common.TokenSigningAlgorithm;
import se.digg.wallet.datatypes.mdl.data.CBORUtils;
import se.digg.wallet.datatypes.mdl.data.DeviceResponse;
import se.digg.wallet.datatypes.mdl.data.IssuerSigned;
import se.digg.wallet.datatypes.mdl.data.MdlPresentationInput;

@Slf4j
class MdlTokenPresenterTest {

  static MdlTokenIssuer tokenIssuer;

  @BeforeAll
  static void setUp() {
    tokenIssuer = new MdlTokenIssuer();
  }

  @Test
  void testCases() throws Exception {
    MdlTokenPresenter defaultPresenter = new MdlTokenPresenter();
    PublicKey walletPublic = TestCredentials.p256_walletKey.toPublicKey();
    PublicKey rsaWalletPublic = TestCredentials.rsa_walletKey.toPublicKey();
    PrivateKey walletPrivate = TestCredentials.p256_walletKey.toPrivateKey();
    PrivateKey rsaWalletPrivate = TestCredentials.rsa_walletKey.toPrivateKey();

    byte[] ecToken = MdlIssuerSignedValidatorTest.getToken(
        tokenIssuer,
        TestCredentials.p256_issuerCredential,
        walletPublic);
    byte[] ecTokenRsaWallet = MdlIssuerSignedValidatorTest.getToken(
        tokenIssuer,
        TestCredentials.p256_issuerCredential,
        rsaWalletPublic);
    byte[] rsaToken = MdlIssuerSignedValidatorTest.getToken(
        tokenIssuer,
        TestCredentials.rsa_issuerCredential,
        walletPublic);

    Map<String, List<String>> allDisclosure = Collections.singletonMap(
        TokenAttributeNameSpace.EUDI_WALLET_PID.getId(),
        List.of(
            "issuance_date",
            "issuing_country",
            "given_name",
            "age_over_18",
            "birth_date",
            "expiry_date",
            "family_name",
            "issuing_authority"));
    Map<String, List<String>> nameDisclosure = Collections.singletonMap(
        TokenAttributeNameSpace.EUDI_WALLET_PID.getId(),
        List.of("given_name", "family_name"));

    performTestCase(
        "Default test case",
        defaultPresenter,
        getInputBuilder(ecToken, allDisclosure).build(),
        walletPrivate,
        null);
    performTestCase(
        "Mac test case",
        defaultPresenter,
        getInputBuilder(ecToken, allDisclosure)
            .clientPublicKey(TestCredentials.p256_clientKey.toPublicKey())
            .macDeviceAuthentication(true)
            .build(),
        walletPrivate,
        null);
    performTestCase(
        "RSA issuer key",
        defaultPresenter,
        getInputBuilder(rsaToken, allDisclosure)
            .algorithm(TokenSigningAlgorithm.ECDSA_256)
            .build(),
        walletPrivate,
        null);
    performTestCase(
        "RSA wallet key",
        defaultPresenter,
        getInputBuilder(ecTokenRsaWallet, nameDisclosure)
            .algorithm(TokenSigningAlgorithm.RSA_PSS_256)
            .build(),
        rsaWalletPrivate,
        null);
    performTestCase(
        "Wrong wallet algorithm",
        defaultPresenter,
        getInputBuilder(ecTokenRsaWallet, nameDisclosure)
            .algorithm(TokenSigningAlgorithm.ECDSA_256)
            .build(),
        rsaWalletPrivate,
        TokenPresentationException.class);
    performTestCase(
        "No token",
        defaultPresenter,
        getInputBuilder(null, allDisclosure).build(),
        walletPrivate,
        TokenPresentationException.class);
    performTestCase(
        "No Response URI",
        defaultPresenter,
        getInputBuilder(ecToken, allDisclosure).responseUri(null).build(),
        walletPrivate,
        TokenPresentationException.class);
    performTestCase(
        "No nonce",
        defaultPresenter,
        getInputBuilder(ecToken, allDisclosure).nonce(null).build(),
        walletPrivate,
        TokenPresentationException.class);
    performTestCase(
        "No algorithm",
        defaultPresenter,
        getInputBuilder(ecToken, allDisclosure).algorithm(null).build(),
        walletPrivate,
        TokenPresentationException.class);
  }

  public static MdlPresentationInput.MdlPresentationInputBuilder getInputBuilder(
      byte[] token,
      Map<String, List<String>> disclosures) {
    return MdlPresentationInput.builder()
        .token(token)
        .clientId("https://example.com/client_id")
        .responseUri("https://example.com/audience")
        .mdocGeneratedNonce("1234567890abcdefgh")
        .nonce("abcdefgh1234567890")
        .algorithm(TokenSigningAlgorithm.ECDSA_256)
        .disclosures(disclosures);
  }

  void performTestCase(
      String description,
      MdlTokenPresenter presenter,
      MdlPresentationInput input,
      PrivateKey walletPrivate,
      Class<? extends Exception> expectedException) throws Exception {
    log.info("TEST CASE:\n================\n{}\n================", description);

    if (expectedException != null) {
      Exception exception = assertThrows(expectedException, () -> {
        presenter.presentToken(input, walletPrivate);
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
      byte[] presentedToken = presenter.presentToken(input, walletPrivate);
      logPresentationToken(presentedToken);
      assertNotNull(presentedToken);
    }
  }

  public static void logPresentationToken(byte[] presentationToken)
      throws Exception {
    log.info("Token CBOR:\n{}", Hex.toHexString(presentationToken));
    DeviceResponse deviceResponse = DeviceResponse.deserialize(
        presentationToken);
    IssuerSigned issuerSigned = deviceResponse.getIssuerSigned();
    issuerSigned
        .getNameSpaces()
        .forEach((ns, v) -> {
          List<String> attributeValPrints = new ArrayList<>();
          v.forEach(issuerSignedItem -> {
            try {
              attributeValPrints.add(
                  CBORUtils.cborToPrettyJson(
                      CBORUtils.CBOR_MAPPER.writeValueAsBytes(issuerSignedItem)));
            } catch (IOException e) {
              throw new RuntimeException(e);
            }
          });
          log.info(
              "Name space: {}\n{}",
              ns,
              String.join("\n", attributeValPrints));
        });
    MdlIssuerSignedValidator validator = new MdlIssuerSignedValidator();
    MdlIssuerSignedValidationResult issuerSignedValidationResult =
        validator.validateToken(
            CBORUtils.CBOR_MAPPER.writeValueAsBytes(issuerSigned),
            null);

    log.info(
        "Mobile security object:\n{}",
        CBORUtils.cborToPrettyJson(
            CBORUtils.CBOR_MAPPER.writeValueAsBytes(
                issuerSignedValidationResult.getMso())));
  }
}

// SPDX-FileCopyrightText: 2024 Digg - Agency for Digital Government
//
// SPDX-License-Identifier: EUPL-1.2

package se.digg.wallet.datatypes.mdl.process;

import java.time.Duration;
import java.util.Collections;
import java.util.List;
import java.util.Map;

import lombok.extern.slf4j.Slf4j;
import org.bouncycastle.util.encoders.Hex;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import se.digg.wallet.datatypes.common.*;
import se.digg.wallet.datatypes.mdl.data.*;
import se.idsec.cose.AlgorithmID;
import se.idsec.cose.COSEKey;
import se.swedenconnect.security.credential.PkiCredential;

@Slf4j
class MdlTokenIssuerTest {

  static PkiCredential issuerCredential;
  static String pidNameSpace;
  static Map<String, List<String>> selectedDisclosures;

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
  }
}

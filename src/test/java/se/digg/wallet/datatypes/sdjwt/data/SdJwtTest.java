// SPDX-FileCopyrightText: 2024 Digg - Agency for Digital Government
//
// SPDX-License-Identifier: EUPL-1.2

package se.digg.wallet.datatypes.sdjwt.data;

import static org.junit.jupiter.api.Assertions.*;

import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSSigner;
import com.nimbusds.jose.crypto.ECDSASigner;
import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.gen.ECKeyGenerator;
import com.nimbusds.jwt.SignedJWT;

import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.security.interfaces.ECPrivateKey;
import java.time.Duration;
import java.util.List;
import java.util.Random;

import lombok.extern.slf4j.Slf4j;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import se.digg.wallet.datatypes.common.*;
import se.digg.wallet.datatypes.common.TestCredentials;
import se.digg.wallet.datatypes.sdjwt.JSONUtils;
import se.digg.wallet.datatypes.sdjwt.process.SdJwtTokenPresenter;
import se.digg.wallet.datatypes.sdjwt.process.SdJwtTokenValidationResult;
import se.digg.wallet.datatypes.sdjwt.process.SdJwtTokenValidator;
import se.digg.wallet.datatypes.sdjwt.process.SdJwtPresentationValidator;
import se.swedenconnect.security.credential.PkiCredential;

@Slf4j
class SdJwtTest {

  public static Random RNG;

  @BeforeAll
  static void setup() {
    RNG = new SecureRandom();
  }

  @Test
  void simpleSdJwtTest() throws Exception {
    ECKey walletKey = new ECKeyGenerator(Curve.P_256).generate();
    PkiCredential issuerCredential = TestCredentials.p256_issuerCredential;
    JWSSigner signer = new ECDSASigner(
      (ECPrivateKey) issuerCredential.getPrivateKey()
    );
    JWSAlgorithm jwsAlgorithm = JWSAlgorithm.ES256;
    TokenDigestAlgorithm sdAlgorithm = TokenDigestAlgorithm.SHA_256;
    Duration validity = Duration.ofDays(1);

    SdJwt sdJwt = SdJwt.builder(
        "https://example.com/pid-issuer",
        sdAlgorithm
      )
      .legacySdJwtType(true)
      .confirmationKey(walletKey.toPublicJWK())
      .verifiableCredentialType("https://example.com/identity_credential")
      .claimsWithDisclosure(
        ClaimsWithDisclosure.builder(sdAlgorithm)
          .disclosure(
            new Disclosure(
              TokenAttribute.builder()
                .type(new TokenAttributeType("given_name"))
                .value("John").build()
            )
          )
          .disclosure(
            new Disclosure(
              TokenAttribute.builder()
                .type(new TokenAttributeType("family_name"))
                .value("Doe").build()
            )
          )
          .disclosure(
            new Disclosure(
              TokenAttribute.builder()
                .type(new TokenAttributeType("email"))
                .value("johndoe@example.com")
                .build()
            )
          )
          .disclosure(
            new Disclosure(
              TokenAttribute.builder()
                .type(new TokenAttributeType("phone_number"))
                .value("+1-202-555-0101")
                .build()
            )
          )
          .disclosure(
            new Disclosure(
              TokenAttribute.builder()
                .type(new TokenAttributeType("birthdate"))
                .value("1940-01-01")
                .build()
            )
          )
          .arrayEntry(
            "nationality",
            new Disclosure(TokenAttribute.builder().value("US").build())
          )
          .arrayEntry(
            "nationality",
            new Disclosure(TokenAttribute.builder().value("DE").build())
          )
          .arrayEntry("nationality", "SE")
          .openClaim("open", "Value")
          .claimsWithDisclosure(
            "address",
            ClaimsWithDisclosure.builder(sdAlgorithm)
              .disclosure(
                new Disclosure(
                  TokenAttribute.builder()
                    .type(new TokenAttributeType("street_address"))
                    .value("123 Main St")
                    .build()
                )
              )
              .disclosure(
                new Disclosure(
                  TokenAttribute.builder()
                    .type(new TokenAttributeType("locality"))
                    .value("Anytown")
                    .build()
                )
              )
              .disclosure(
                new Disclosure(
                  TokenAttribute.builder()
                    .type(new TokenAttributeType("region"))
                    .value("Anystate")
                    .build()
                )
              )
              .disclosure(
                new Disclosure(
                  TokenAttribute.builder()
                    .type(new TokenAttributeType("country"))
                    .value("US").build()
                )
              )
              .build()
          )
          .build()
      )
      .build(
        issuerCredential,
        validity,
        jwsAlgorithm,
        signer,
        issuerCredential.getName()
      );
    sdJwt.protectedPresentation(
      new ECDSASigner(walletKey.toECPrivateKey()),
      JWSAlgorithm.ES256,
      "https://example.com/aud",
      "nonce_12345",
      null
    );

    SignedJWT issuerSignedJwt = sdJwt.getIssuerSigned();
    log.info("Issuer Signed JWT:\n{}", issuerSignedJwt.serialize());
    String unprotectedPresentation = sdJwt.unprotectedPresentation(null);
    log.info(
      "Complete unprotected persentation: \n{}",
      unprotectedPresentation
    );

    // Parse unprotected
    SdJwt parsedSdJwt = SdJwt.parse(unprotectedPresentation);
    assertNotNull(parsedSdJwt);

    String nonce = JSONUtils.base64URLString(new BigInteger(64, RNG).toByteArray());
    SdJwtPresentationInput presentationInput = SdJwtPresentationInput.builder()
      .algorithm(TokenSigningAlgorithm.ECDSA_256)
      .token(unprotectedPresentation.getBytes())
      .audience("http://example.com/audience")
      .nonce(nonce)
      .build();

    SdJwtTokenPresenter tokenPresenter = new SdJwtTokenPresenter();
    byte[] presentedToken = tokenPresenter.presentToken(presentationInput, walletKey.toECPrivateKey());
    assertNotNull(presentedToken);

    log.info("\nProtected presentation with disclosures:\n{}", new String(presentedToken));

    log.info(
      "Token Payload:\n{}",
      JSONUtils.JSON_MAPPER.writerWithDefaultPrettyPrinter()
        .writeValueAsString(
          sdJwt.getIssuerSigned().getJWTClaimsSet().getClaims()
        )
    );

    List<Disclosure> allDisclosures = sdJwt.getDisclosures();
    log.info("Disclosures:\n------------------");
    for (Disclosure disclosure : allDisclosures) {
      String disclosureString = JSONUtils.base64URLString(
        disclosure.getDisclosure().getBytes(StandardCharsets.UTF_8)
      );
      log.info(
        "Disclosure hash: {}",
        JSONUtils.base64URLString(
          JSONUtils.disclosureHash(disclosure, sdAlgorithm.getJdkName())
        )
      );
      log.info("Disclosure str: {}", disclosureString);
      log.info("Disclosure: {}", disclosure.getDisclosure());
    }

    // Validate and reconstruct disclosed credentials;
    SdJwtTokenValidator validator = new SdJwtTokenValidator();
    SdJwtTokenValidationResult validationResult =
      validator.validateToken(presentedToken, null);

    log.info(
      "Disclosed payload:\n{}",
      JSONUtils.JSON_MAPPER.writerWithDefaultPrettyPrinter()
        .writeValueAsString(validationResult.getDisclosedTokenPayload().toJSONObject())
    );

    // Finally testing the presentation validator
    SdJwtPresentationValidator presentationValidator = new SdJwtPresentationValidator();
    TokenValidationResult presentationValidationResult = presentationValidator.validatePresentation(
      presentedToken,
      new SdJwtPresentationValidationInput(nonce, "http://example.com/audience"),
      List.of(TrustedKey.builder()
        .certificate(issuerCredential.getCertificate())
        .build())
    );

  }
}

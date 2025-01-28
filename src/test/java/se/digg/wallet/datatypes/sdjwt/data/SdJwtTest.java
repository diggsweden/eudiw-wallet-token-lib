package se.digg.wallet.datatypes.sdjwt.data;

import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSSigner;
import com.nimbusds.jose.Payload;
import com.nimbusds.jose.crypto.ECDSASigner;
import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.gen.ECKeyGenerator;
import com.nimbusds.jwt.SignedJWT;
import lombok.extern.slf4j.Slf4j;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import se.digg.wallet.datatypes.common.TokenAttribute;
import se.digg.wallet.datatypes.common.TokenValidationResult;
import se.digg.wallet.datatypes.mdl.data.TestCredentials;
import se.digg.wallet.datatypes.sdjwt.JSONUtils;
import se.digg.wallet.datatypes.sdjwt.process.SdJwtTokenValidator;
import se.swedenconnect.security.credential.PkiCredential;

import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.security.interfaces.ECPrivateKey;
import java.time.Duration;
import java.util.List;
import java.util.Random;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Description
 */
@Slf4j
class SdJwtTest {

  public static Random RNG;

  @BeforeAll
  static void setup() {
    RNG = new SecureRandom();
  }

  @Test
  void simpleSdJwtTest() throws  Exception {

    ECKey walletKey = new ECKeyGenerator(Curve.P_256).generate();
    PkiCredential issuerCredential = TestCredentials.issuerCredential;
    JWSSigner signer = new ECDSASigner((ECPrivateKey) issuerCredential.getPrivateKey());
    JWSAlgorithm jwsAlgorithm = JWSAlgorithm.ES256;
    String sdAlgorithm = "SHA-256";
    Duration validity = Duration.ofDays(1);

    SdJwt sdJwt = SdJwt.issuerSignedBuilder("https://example.com/pid-issuer", sdAlgorithm)
      .confirmationKey(walletKey.toPublicJWK())
      .verifiableCredentialType("https://example.com/identity_credential")
      .claimsWithDisclosure(ClaimsWithDisclosure.builder(sdAlgorithm)
        .disclosure(new Disclosure(TokenAttribute.builder()
          .name("given_name").value("John").build()))
        .disclosure(new Disclosure(TokenAttribute.builder()
          .name("family_name").value("Doe").build()))
        .disclosure(new Disclosure(TokenAttribute.builder()
          .name("email").value("johndoe@example.com").build()))
        .disclosure(new Disclosure(TokenAttribute.builder()
          .name("phone_number").value("+1-202-555-0101").build()))
        .disclosure(new Disclosure(TokenAttribute.builder()
          .name("birthdate").value("1940-01-01").build()))
        .arrayEntry("nationality", new Disclosure(TokenAttribute.builder().value("US").build()))
        .arrayEntry("nationality", new Disclosure(TokenAttribute.builder().value("DE").build()))
        .arrayEntry("nationality", "SE")
        .openClaim("open", "Value")
        .claimsWithDisclosure("address", ClaimsWithDisclosure.builder(sdAlgorithm)
          .disclosure(new Disclosure(TokenAttribute.builder()
            .name("street_address").value("123 Main St").build()))
          .disclosure(new Disclosure(TokenAttribute.builder()
            .name("locality").value("Anytown").build()))
          .disclosure(new Disclosure(TokenAttribute.builder()
            .name("region").value("Anystate").build()))
          .disclosure(new Disclosure(TokenAttribute.builder()
            .name("country").value("US").build()))
          .build())
        .build())
      .build(
        issuerCredential,
        validity,
        jwsAlgorithm,
        signer,
        issuerCredential.getName()
      );
    sdJwt.protectedPresentation(
      new ECDSASigner(walletKey.toECPrivateKey()),
      JWSAlgorithm.ES256,"https://example.com/aud", "nonce_12345",
      null
    );

    SignedJWT issuerSignedJwt = sdJwt.getIssuerSigned();
    log.info("Issuer Signed JWT:\n{}", issuerSignedJwt.serialize());
    String unprotectedPresentation = sdJwt.unprotectedPresentation(null);
    log.info("Complete unprotected persentation: \n{}", unprotectedPresentation);

    // Parse unprotected
    SdJwt parsedSdJwt = SdJwt.parse(unprotectedPresentation);
    assertNotNull(parsedSdJwt);

    // Sign presentation:
    JWSSigner presentationSigner = new ECDSASigner(walletKey.toECPrivateKey());
    String sdJwtVP = sdJwt.protectedPresentation(presentationSigner, jwsAlgorithm, "http://example.com/audience",
      JSONUtils.base64URLString(new BigInteger(64, RNG).toByteArray()),
      null);

    log.info("\nProtected presentation with disclosures:\n{}", sdJwtVP);

    log.info("Token Payload:\n{}", JSONUtils.JSON_MAPPER.writerWithDefaultPrettyPrinter().writeValueAsString(sdJwt.getIssuerSigned().getJWTClaimsSet().getClaims()));

    List<Disclosure> allDisclosures = sdJwt.getClaimsWithDisclosure().getAllDisclosures();
    log.info("Disclosures:\n------------------");
    for (Disclosure disclosure : allDisclosures) {
      String disclosureString = JSONUtils.base64URLString(disclosure.getDisclosure().getBytes(StandardCharsets.UTF_8));
      log.info("Disclosure hash: {}", JSONUtils.base64URLString(JSONUtils.disclosureHash(disclosure, sdAlgorithm)));
      log.info("Disclosure str: {}", disclosureString);
      log.info("Disclosure: {}", disclosure.getDisclosure());
    }

    // Validate and reconstruct disclosed credentials;
    SdJwtTokenValidator validator = new SdJwtTokenValidator();
    TokenValidationResult<SdJwt, Payload> validationResult = validator.validateToken(
      sdJwtVP.getBytes(StandardCharsets.UTF_8), null);

    log.info("Disclosed payload:\n{}", JSONUtils.JSON_MAPPER.writerWithDefaultPrettyPrinter().writeValueAsString(validationResult.getTokenPayload().toJSONObject()));

  }
}
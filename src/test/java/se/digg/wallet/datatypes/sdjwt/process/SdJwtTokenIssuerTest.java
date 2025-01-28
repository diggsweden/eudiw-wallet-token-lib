package se.digg.wallet.datatypes.sdjwt.process;

import se.idsec.cose.AlgorithmID;
import se.idsec.cose.COSEKey;
import com.nimbusds.jose.Payload;
import com.nimbusds.jwt.SignedJWT;
import lombok.extern.slf4j.Slf4j;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import se.digg.wallet.datatypes.common.TokenAttribute;
import se.digg.wallet.datatypes.common.TokenDigestAlgorithm;
import se.digg.wallet.datatypes.common.TokenSigningAlgorithm;
import se.digg.wallet.datatypes.common.TokenValidationResult;
import se.digg.wallet.datatypes.mdl.data.TestCredentials;
import se.digg.wallet.datatypes.mdl.data.TestData;
import se.digg.wallet.datatypes.sdjwt.JSONUtils;
import se.digg.wallet.datatypes.sdjwt.data.ClaimsWithDisclosure;
import se.digg.wallet.datatypes.sdjwt.data.Disclosure;
import se.digg.wallet.datatypes.sdjwt.data.SdJwt;
import se.swedenconnect.security.credential.PkiCredential;

import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.Random;

/**
 * Description
 */
@Slf4j
class SdJwtTokenIssuerTest {

  public static final Random RNG = new SecureRandom();

  static PkiCredential issuerCredential;

  @BeforeAll
  static void setUp() {
    issuerCredential = TestCredentials.issuerCredential;
  }

  @Test
  void simpleIssueTest() throws Exception{
    TokenSigningAlgorithm algorithm = TokenSigningAlgorithm.ECDSA_256;
    TokenDigestAlgorithm digestAlgorithm = algorithm.getDigestAlgorithm();
    SdJwtTokenInput tokenInput = SdJwtTokenInput.sdJwtINputBuilder()
      .issuer("http://example.com/issuer")
      .issuerCredential(issuerCredential)
      .algorithm(algorithm)
      .expirationDuration(Duration.ofDays(1))
      .walletPublicKey(COSEKey.generateKey(AlgorithmID.ECDSA_256).AsPublicKey())
      .claimsWithDisclosure(ClaimsWithDisclosure.builder(digestAlgorithm.getJdkName())
        .openClaim("open_claim", "claim-value")
        .disclosure(new Disclosure(TokenAttribute.builder().name("given_name").value("John").build()))
        .disclosure(new Disclosure(TokenAttribute.builder().name("Surname").value("Doe").build()))
        .build())
      .build();
    SdJwtTokenIssuer tokenIssuer = new SdJwtTokenIssuer();
    String token = new String(tokenIssuer.issueToken(tokenInput), StandardCharsets.UTF_8);
    logToken(token, digestAlgorithm.getJdkName());
  }

  /**
   * Method to test the issuance of a credential token and perform selective disclosure.
   *
   * @throws Exception if an error occurs during the test execution
   */
  @Test
  void issueCredentialTest() throws Exception{
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
    String token = new String(tokenIssuer.issueToken(tokenInput), StandardCharsets.UTF_8);
    // Log issued token
    logToken(token, ecdsa256.getDigestAlgorithm().getJdkName());

    //  Selective disclosure in wallet
    SdJwt parsed = SdJwt.parse(token);
    // Get all available disclosures
    List<Disclosure> allDisclosures = parsed.getClaimsWithDisclosure().getAllDisclosures();
    // Reduce the list of disclosures
    List<String> userDisclosures = filterDisclosure(allDisclosures, List.of("given_name", "birth_date", "family_name", "issuing_authority"));
    // Get the reduced list to sign
    String unprotectedPresentation = parsed.unprotectedPresentation(userDisclosures);
    // Sign the reduced disclosures with the wallet private key
    String protectededPresentation = parsed.protectedPresentation(ecdsa256.jwsSigner(walletKeyPair.AsPrivateKey()), ecdsa256.getJwsAlgorithm(),
      "http://example.com/aud",
      JSONUtils.base64URLString(new BigInteger(128, RNG).negate().toByteArray()), userDisclosures
    );
    // Log result
    logToken(protectededPresentation, ecdsa256.getDigestAlgorithm().getJdkName());

    SdJwtTokenValidator tokenValidator = new SdJwtTokenValidator();
    TokenValidationResult<SdJwt, Payload> validationResult = tokenValidator.validateToken(
      protectededPresentation.getBytes(StandardCharsets.UTF_8), null);
  }


  private List<String> filterDisclosure(List<Disclosure> allDisclosures, List<String> selectedNames) {
    List<String> filteredDisclosures = new ArrayList<>();
    for (Disclosure disclosure : allDisclosures) {
      if (selectedNames.contains(disclosure.getName())) {
        filteredDisclosures.add(JSONUtils.base64URLString(disclosure.getDisclosure().getBytes(StandardCharsets.UTF_8)));
      }
    }
    return filteredDisclosures;
  }

  void logToken(String token, String digestAlgo) throws Exception {
    log.info("Issued sdJwt token: \n{}", token);

    String[] split = token.split("~");
    log.info("Token header:\n{}", JSONUtils.JSON_MAPPER.writerWithDefaultPrettyPrinter().writeValueAsString(
      SignedJWT.parse(split[0]).getHeader().toJSONObject()
    ));
    log.info("Token payload:\n{}", JSONUtils.JSON_MAPPER.writerWithDefaultPrettyPrinter().writeValueAsString(
      SignedJWT.parse(split[0]).getJWTClaimsSet().getClaims()
    ));
    log.info("Disclosures: ");

    int end = token.endsWith("~") ? split.length : split.length -1;

    for (int i = 1 ; i<end ; i++) {
      String disclosureB64 = split[i];
      Disclosure disclosure = new Disclosure(disclosureB64);
      log.info("Disclosure hash: {}", JSONUtils.base64URLString(JSONUtils.disclosureHash(disclosure, digestAlgo)));
      log.info("Disclosure str: {}", disclosureB64);
      log.info("Disclosure: {}", disclosure.getDisclosure());
    }

    if (!token.endsWith("~")) {
      SignedJWT cnfJwt = SignedJWT.parse(split[split.length - 1]);
      log.info("Token header:\n{}", JSONUtils.JSON_MAPPER.writerWithDefaultPrettyPrinter().writeValueAsString(
        cnfJwt.getHeader().toJSONObject()
      ));
      log.info("Token payload:\n{}", JSONUtils.JSON_MAPPER.writerWithDefaultPrettyPrinter().writeValueAsString(
        cnfJwt.getJWTClaimsSet().getClaims()
      ));
    }

  }

}
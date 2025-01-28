package se.digg.wallet.datatypes.mdl.process;

import se.idsec.cose.AlgorithmID;
import se.idsec.cose.COSEKey;
import com.nimbusds.jose.JWSAlgorithm;
import lombok.extern.slf4j.Slf4j;
import org.bouncycastle.util.encoders.Hex;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import se.digg.wallet.datatypes.common.TokenInput;
import se.digg.wallet.datatypes.common.TokenSigningAlgorithm;
import se.digg.wallet.datatypes.common.TokenValidationResult;
import se.digg.wallet.datatypes.common.TrustedKey;
import se.digg.wallet.datatypes.mdl.data.IssuerSigned;
import se.digg.wallet.datatypes.mdl.data.MobileSecurityObject;
import se.digg.wallet.datatypes.mdl.data.TestCredentials;
import se.digg.wallet.datatypes.mdl.data.TestData;
import se.swedenconnect.security.credential.PkiCredential;

import java.time.Duration;
import java.util.List;

/**
 * Description
 */
@Slf4j
class MdlTokenIssuerTest {

  static PkiCredential issuerCredential;
  static String pidNameSpace;

  @BeforeAll
  static void setUp() {
    issuerCredential = TestCredentials.issuerCredential;
    pidNameSpace = "eu.europa.ec.eudi.pid.1";
  }

  @Test
  void issueCredentialTest() throws Exception{

    TokenInput tokenInput = TokenInput.builder()
      .issuerCredential(issuerCredential)
      .algorithm(TokenSigningAlgorithm.ECDSA_256)
      .expirationDuration(Duration.ofDays(1))
      .walletPublicKey(COSEKey.generateKey(AlgorithmID.ECDSA_256).AsPublicKey())
      .attributes(TestData.defaultPidUserAttributes)
      .build();
    MdlTokenIssuer tokenIssuer = new MdlTokenIssuer(true);
    byte[] token = tokenIssuer.issueToken(tokenInput);
    log.info("Issued mdL token: \n{}", Hex.toHexString(token));

    MdlIssuerSignedValidator validator = new MdlIssuerSignedValidator();
    TokenValidationResult<IssuerSigned, MobileSecurityObject> validationResult = validator.validateToken(
      token, List.of(TrustedKey.builder()
        .certificate(issuerCredential.getCertificate())
        .build()));

    log.info("Token validation passed");
  }

}
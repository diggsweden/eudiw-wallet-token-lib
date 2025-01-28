package se.digg.wallet.datatypes.sdjwt.data;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.nimbusds.jose.*;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.util.Base64;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import lombok.Data;
import se.digg.wallet.datatypes.common.TokenValidationException;
import se.digg.wallet.datatypes.sdjwt.JSONUtils;
import se.swedenconnect.security.credential.PkiCredential;

import java.nio.charset.StandardCharsets;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateEncodingException;
import java.text.ParseException;
import java.time.Duration;
import java.time.Instant;
import java.util.*;

/**
 * This class holds the information elements of a Selective Disclosure JWT.
 */
@Data
public class SdJwt {

  public static final String SD_JWT_TYPE = "dc+sd-jwt";
  public static final String KB_JWT_TYPE = "kb+jwt";
  public static final List<String> STD_CLAIMS = List.of("iss", "nbf", "exp", "cnf", "vct", "status", "sub", "iat", "_sd_alg");

  private String issuer;
  private JWK confirmationKey;
  private String vcType;
  private Object status;
  private String subject;
  private String sdAlgorithm;
  private ClaimsWithDisclosure claimsWithDisclosure;
  private SignedJWT issuerSigned;
  private SignedJWT walletSigned;

  public static SdJwtBuilder issuerSignedBuilder(String issuer, String sdAlg) {
    return new SdJwtBuilder(issuer, sdAlg);
  }

  public String tokenWithDisclosures() {
    StringBuilder sdJwtVP = new StringBuilder()
      .append(issuerSigned.serialize())
      .append("~");
    List<Disclosure> allDisclosures = Optional.ofNullable(getClaimsWithDisclosure())
      .orElse(ClaimsWithDisclosure.builder(sdAlgorithm).build()).getAllDisclosures();
    for (Disclosure disclosure : allDisclosures) {
      String disclosureStr = JSONUtils.base64URLString(disclosure.getDisclosure().getBytes(StandardCharsets.UTF_8));
      sdJwtVP.append(disclosureStr).append("~");
    }
    return sdJwtVP.toString();
  }

  /**
   * Generates an unprotected verifiable presentation.
   *
   * @param disclosures a list of specific disclosures to reveal to the verifier. If null, all available attribute disclosures will be included.
   * @return a string representing the verifiable presentation with the specified disclosures
   */
  public String unprotectedPresentation(List<String> disclosures) {
    StringBuilder sdJwtVP = new StringBuilder();
    if (disclosures == null) {
      // If null value, then include all attribute disclosures
      sdJwtVP.append(tokenWithDisclosures());
    }
    else {
      // If specific list, then only include these disclosures in the presentation
      sdJwtVP.append(issuerSigned.serialize()).append("~");
      for (String disclosureStr : disclosures) {
        sdJwtVP.append(disclosureStr).append("~");
      }
    }
    return sdJwtVP.toString();
  }

  public String protectedPresentation(JWSSigner signer, JWSAlgorithm algorithm, String aud, String nonce,
    List<String> disclosures) throws NoSuchAlgorithmException, JOSEException {
    String unprotectedPresentation = unprotectedPresentation(disclosures);
    final JWTClaimsSet.Builder claimsBuilder = new JWTClaimsSet.Builder()
      .issueTime(new Date())
      .audience(aud)
      .claim("nonce", nonce)
      .claim("sd_hash", JSONUtils.b64UrlHash(unprotectedPresentation.getBytes(StandardCharsets.UTF_8), sdAlgorithm));

    final SignedJWT walletSignedJwt = new SignedJWT(
      new JWSHeader.Builder(algorithm)
        .type(new JOSEObjectType(KB_JWT_TYPE))
        .build(),
      claimsBuilder
        .build());
    walletSignedJwt.sign(signer);
    setWalletSigned(walletSignedJwt);
    return unprotectedPresentation + walletSignedJwt.serialize();
  }

  /**
   * Builder class for creating an SdJwt object with various properties.
   */
  public static class SdJwtBuilder {

    private final SdJwt sdJwt;

    public SdJwtBuilder(String issuer, String sdAlg) {
      sdJwt = new SdJwt();
      sdJwt.setIssuer(issuer);
      sdJwt.setSdAlgorithm(sdAlg);
    }

    public SdJwtBuilder claimsWithDisclosure(ClaimsWithDisclosure claimsWithDisclosure) {
      sdJwt.setClaimsWithDisclosure(claimsWithDisclosure);
      return this;
    }

    public SdJwtBuilder confirmationKey(JWK walletPublic) {
      sdJwt.setConfirmationKey(walletPublic);
      return this;
    }

    public SdJwtBuilder verifiableCredentialType(String vcType) {
      sdJwt.setVcType(vcType);
      return this;
    }

    public SdJwtBuilder status(Object status) {
      sdJwt.setStatus(status);
      return this;
    }

    public SdJwtBuilder subject(String subject) {
      sdJwt.setSubject(subject);
      return this;
    }

    public SdJwt build(PkiCredential issuerCredential, Duration validity, JWSAlgorithm algorithm, JWSSigner signer, String kid)
      throws JOSEException, NoSuchAlgorithmException, CertificateEncodingException {

      final JWTClaimsSet.Builder claimsBuilder = new JWTClaimsSet.Builder()
        .issuer(sdJwt.getIssuer())
        .subject(sdJwt.getSubject())
        .issueTime(new Date())
        .expirationTime(Date.from(Instant.now().plus(validity)))
        .claim("vct", sdJwt.getVcType())
        .claim("_sd_alg", sdJwt.getSdAlgorithm())
        .claim("cnf", sdJwt.getConfirmationKey() != null
          ? Collections.singletonMap("jwk", sdJwt.confirmationKey.toJSONObject())
          : null)
        .claim("status", sdJwt.getStatus());

      ClaimsWithDisclosure cwd = sdJwt.getClaimsWithDisclosure();
      cwd.getAllSupportingClaims().forEach((key, value) -> claimsBuilder.claim(key, value));
      // Create JWT
      final SignedJWT jwt = new SignedJWT(
        new JWSHeader.Builder(algorithm)
          .keyID(kid)
          .x509CertChain(List.of(Base64.encode(issuerCredential.getCertificate().getEncoded())))
          .type(new JOSEObjectType(SD_JWT_TYPE))
          .build(),
        claimsBuilder
          .build());
      jwt.sign(signer);
      sdJwt.setIssuerSigned(jwt);
      return sdJwt;
    }
  }

  public static SdJwt parse(String presentation) throws TokenValidationException {
    if (presentation == null) {
      throw new TokenValidationException("No data");
    }
    SdJwt sdJwt = new SdJwt();
    SignedJWT issuerSignedJwt;
    List<Disclosure> disclosureList;
    SignedJWT walletConfirmationJwt = null;
    String[] split = presentation.split("~");
    try {
      issuerSignedJwt = SignedJWT.parse(split[0]);
      int start = 1;
      int end = split.length;
      if (!presentation.endsWith("~")) {
        walletConfirmationJwt = SignedJWT.parse(split[split.length - 1]);
        end = split.length - 1;
      }
      disclosureList = new ArrayList<>();
      for (int i = start; i < end; i++) {
        disclosureList.add(new Disclosure(split[i]));
      }
      sdJwt.setIssuerSigned(issuerSignedJwt);
      sdJwt.setWalletSigned(walletConfirmationJwt);

      JWTClaimsSet claimsSet = issuerSignedJwt.getJWTClaimsSet();
      JWK confirmationKey = parseConfirmationKey(claimsSet.getClaim("cnf"));
      Map<String, Object> claimsMap = new HashMap<>(claimsSet.getClaims());
      String sdAlgo = (String) claimsMap.get("_sd_alg");
      sdJwt.setSdAlgorithm(sdAlgo);
      sdJwt.setIssuer(claimsSet.getIssuer());
      sdJwt.setSubject(claimsSet.getSubject());
      sdJwt.setStatus(claimsSet.getClaim("status"));
      sdJwt.setConfirmationKey(confirmationKey);
      STD_CLAIMS.forEach(claimsMap::remove);
      if (claimsMap.containsKey("_sd")) {
        sdJwt.setClaimsWithDisclosure(ClaimsWithDisclosure.parse(claimsMap, disclosureList, sdAlgo));
      }

      return sdJwt;

    }
    catch (ParseException | JsonProcessingException | NoSuchAlgorithmException e) {
      throw new TokenValidationException("Unable to parse token data", e);
    }

  }

  public static JWK parseConfirmationKey(Object cnf) throws TokenValidationException, ParseException {
    if (cnf == null) {
      return null;
    }
    if (cnf instanceof Map<?, ?> confirmationMap) {
      if (confirmationMap.get("jwk") instanceof Map<?, ?> jwkMap) {
        return JWK.parse((Map<String, Object>) jwkMap);
      }
      else {
        throw new TokenValidationException("No JWK key in cnf claim");
      }
    }
    else {
      throw new TokenValidationException("Invalid confirmation key format");
    }
  }

}

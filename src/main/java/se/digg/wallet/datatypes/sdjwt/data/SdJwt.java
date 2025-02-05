// SPDX-FileCopyrightText: 2024 Digg - Agency for Digital Government
//
// SPDX-License-Identifier: EUPL-1.2

package se.digg.wallet.datatypes.sdjwt.data;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.nimbusds.jose.*;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.util.Base64;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import java.nio.charset.StandardCharsets;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateEncodingException;
import java.text.ParseException;
import java.time.Duration;
import java.time.Instant;
import java.util.*;
import lombok.Data;
import se.digg.wallet.datatypes.common.TokenDigestAlgorithm;
import se.digg.wallet.datatypes.common.TokenValidationException;
import se.digg.wallet.datatypes.sdjwt.JSONUtils;
import se.swedenconnect.security.credential.PkiCredential;

/**
 * This class holds the information elements of a Selective Disclosure JWT.
 */
@Data
public class SdJwt {

  /**
   * A constant representing a JOSE object type for a selective disclosure JSON Web Token (SD-JWT).
   * The value "dc+sd-jwt" specifies the type used for distinguishing this specialized token format.
   * This constant is useful in scenarios where the JOSE header of a JWT is explicitly required
   * to indicate the SD-JWT type for proper parsing, validation, and processing.
   */
  public static final JOSEObjectType SD_JWT_TYPE = new JOSEObjectType("dc+sd-jwt");
  /**
   * Represents a legacy SD-JWT (Selective Disclosure JSON Web Token) object type 
   * specifically utilized for compatibility with older implementations.
   * <p>
   * This constant defines the JOSE (JavaScript Object Signing and Encryption) object
   * type with a value of "vc+sd-jwt" for encoding verifiable credentials in the
   * selective disclosure format. It is typically used within legacy systems or applications
   * that require adherence to earlier specifications.
   * <p>
   * Within the SD-JWT process, this type aids in identifying tokens using the legacy
   * structure, distinguishing them from other SD-JWT or verifiable presentation types.
   */
  public static final JOSEObjectType SD_JWT_TYPE_LEGACY = new JOSEObjectType("vc+sd-jwt");
  /**
   * Represents the specific JOSE Object Type "kb+jwt" associated with 
   * Key Binding JSON Web Tokens.
   */
  public static final JOSEObjectType KB_JWT_TYPE = new JOSEObjectType("kb+jwt");
  /**
   * Represents a predefined, immutable list of standard claims commonly used in SD-JWT (Selective Disclosure JWT) implementations.
   * <p>
   * These claims serve specific purposes in the structure and verification of SD-JWTs:
   * <ul>
   * <li>"iss": Refers to the issuer of the token.</li>
   * <li>"nbf": Not before claim, specifying when the token becomes valid.</li>
   * <li>"exp": Expiry claim, indicating when the token expires.</li>
   * <li>"cnf": Confirmation key claim, used for proof of key possession.</li>
   * <li>"vct": Claim denoting the verifiable credential type.</li>
   * <li>"status": A claim representing the status of the credential or token.</li>
   * <li>"sub": Subject claim, identifying the subject of the token.</li>
   * <li>"iat": Issued at claim, representing the timestamp of token issuance.</li>
   * <li>"_sd_alg": Indicates the algorithm used for selective disclosure.</li>
   * </ul>
   * <p>
   * This list is used to identify and process these standard claims in the context of SD-JWT operations.
   */
  public static final List<String> STD_CLAIMS = List.of(
    "iss",
    "nbf",
    "exp",
    "cnf",
    "vct",
    "status",
    "sub",
    "iat",
    "_sd_alg"
  );

  /** The selected JWT type included in the SD JWT header */
  private JOSEObjectType jwtType = SD_JWT_TYPE;
  /** Name of the issuer of the SD JWT */
  private String issuer;
  /** The wallet public key bound to the token */
  private JWK confirmationKey;
  /** Type of verifiable credential in the SD JWT */
  private String vcType;
  /** Status information */
  private Object status;
  /** Optional subject identifier of the SD JWT */
  private String subject;
  /** The digest algorithm used to handle disclosures */
  private TokenDigestAlgorithm sdAlgorithm;
  /** Claims with selective disclosure */
  private ClaimsWithDisclosure claimsWithDisclosure;
  /** Signed JWT signed by the issuer */
  private SignedJWT issuerSigned;
  /** Key binding proof signed by the wallet */
  private SignedJWT walletSigned;

  public static SdJwtBuilder builder(String issuer, TokenDigestAlgorithm sdAlg) {
    return new SdJwtBuilder(issuer, sdAlg);
  }

  /**
   * Generates a token containing the issuer-signed SD-JWT appended with disclosures, each separated by a tilde (~).
   * The disclosures are retrieved using the `getDisclosures` method and encoded in Base64URL format.
   *
   * @return A concatenated string consisting of the issuer-signed token followed by the encoded disclosures,
   *         each separated by a tilde (~).
   */
  public String tokenWithDisclosures() {
    StringBuilder sdJwtVP = new StringBuilder()
      .append(issuerSigned.serialize())
      .append("~");
    List<Disclosure> allDisclosures = getDisclosures();
    for (Disclosure disclosure : allDisclosures) {
      String disclosureStr = JSONUtils.base64URLString(
        disclosure.getDisclosure().getBytes(StandardCharsets.UTF_8));
      sdJwtVP.append(disclosureStr).append("~");
    }
    return sdJwtVP.toString();
  }

  /**
   * Retrieves a list of all disclosures associated with the SD-JWT.
   * If no disclosures are available, an empty list will be returned.
   *
   * @return a List of Disclosure objects representing the disclosures linked to the SD-JWT.
   */
  public List<Disclosure> getDisclosures() {
    return Optional.ofNullable(getClaimsWithDisclosure())
      .orElse(ClaimsWithDisclosure.builder(sdAlgorithm).build())
      .getAllDisclosures();
  }

  /**
   * Generates an unprotected verifiable presentation. 
   * <p>
   *   The disclosures is a list of the disclosures that should be included in the verifiable presentation.
   *   This list contains either a list of attribute names, or a list of the complete disclosures (Base64URL encoded).
   *   Any disclosure that match either the full Base64URL encoded disclosure, or the attribute name, will be included.
   * </p>
   *
   * @param disclosures a list of specific disclosures to reveal to the verifier. If null, all available attribute disclosures will be included.
   * @return a string representing the verifiable presentation with the specified disclosures
   */
  public String unprotectedPresentation(List<String> disclosures) {

    StringBuilder sdJwtVP = new StringBuilder();
    if (disclosures == null) {
      // If null value, then include all attribute disclosures
      sdJwtVP.append(tokenWithDisclosures());
    } else {
      // If specific list, then only include these disclosures in the presentation
      List<Disclosure> allDisclosures = getDisclosures();
      List<String> disclosureImages = new ArrayList<>();
      for (Disclosure disclosure : allDisclosures) {
        String disclosureStr = JSONUtils.base64URLString(
          disclosure.getDisclosure().getBytes(StandardCharsets.UTF_8));
        if (disclosures.contains(disclosure.getName()) || disclosures.contains(disclosureStr)) {
          disclosureImages.add(disclosureStr);
        }
      }
      sdJwtVP.append(issuerSigned.serialize()).append("~");
      for (String disclosureStr : disclosureImages) {
        sdJwtVP.append(disclosureStr).append("~");
      }
    }
    return sdJwtVP.toString();
  }

  /**
   * Generates a protected verifiable presentation by signing the claims with the provided signer and algorithm
   * with the wallet private key.
   * The resulting presentation includes both unprotected and protected components.
   * <p>
   *   The disclosures is a list of the disclosures that should be included in the verifiable presentation.
   *   This list contains either a list of attribute names, or a list of the complete disclosures (Base64URL encoded).
   *   Any disclosure that match either the full Base64URL encoded disclosure, or the attribute name, will be included.
   * </p>
   *
   * @param signer the JWSSigner used to sign the claims.
   * @param algorithm the JWSAlgorithm used for the signing process.
   * @param aud the audience value to include in the claims.
   * @param nonce a unique nonce value to include in the claims.
   * @param disclosures a list of specific disclosures to reveal in the presentation.
   *                    If null, all disclosures are included.
   * @return a string representing the combined unprotected and protected verifiable presentation.
   * @throws NoSuchAlgorithmException if the specified hashing algorithm is not available.
   * @throws JOSEException if an error occurs during the signing process.
   */
  public String protectedPresentation(
    JWSSigner signer,
    JWSAlgorithm algorithm,
    String aud,
    String nonce,
    List<String> disclosures
  ) throws NoSuchAlgorithmException, JOSEException {
    String unprotectedPresentation = unprotectedPresentation(disclosures);
    final JWTClaimsSet.Builder claimsBuilder = new JWTClaimsSet.Builder()
      .issueTime(new Date())
      .audience(aud)
      .claim("nonce", nonce)
      .claim(
        "sd_hash",
        JSONUtils.b64UrlHash(
          unprotectedPresentation.getBytes(StandardCharsets.UTF_8),
          sdAlgorithm.getJdkName()
        )
      );

    final SignedJWT walletSignedJwt = new SignedJWT(
      new JWSHeader.Builder(algorithm)
        .type(KB_JWT_TYPE)
        .build(),
      claimsBuilder.build()
    );
    walletSignedJwt.sign(signer);
    setWalletSigned(walletSignedJwt);
    return unprotectedPresentation + walletSignedJwt.serialize();
  }

  /**
   * Builder class for creating an SdJwt object with various properties.
   */
  public static class SdJwtBuilder {

    private final SdJwt sdJwt;

    public SdJwtBuilder(String issuer, TokenDigestAlgorithm sdAlg) {
      Objects.requireNonNull(issuer, "issuer must not be null");
      Objects.requireNonNull(sdAlg, "sd_alg must not be null");
      sdJwt = new SdJwt();
      sdJwt.setIssuer(issuer);
      sdJwt.setSdAlgorithm(sdAlg);
    }

    public SdJwtBuilder claimsWithDisclosure(
      ClaimsWithDisclosure claimsWithDisclosure
    ) {
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
    public SdJwtBuilder legacySdJwtType(boolean legacySdJwtType) {
      sdJwt.setJwtType(legacySdJwtType ? SD_JWT_TYPE_LEGACY : SD_JWT_TYPE);
      return this;
    }

    public SdJwt build(
      PkiCredential issuerCredential,
      Duration validity,
      JWSAlgorithm algorithm,
      JWSSigner signer,
      String kid
    )
      throws JOSEException, NoSuchAlgorithmException, CertificateEncodingException {
      final JWTClaimsSet.Builder claimsBuilder = new JWTClaimsSet.Builder()
        .issuer(sdJwt.getIssuer())
        .subject(sdJwt.getSubject())
        .issueTime(new Date())
        .expirationTime(Date.from(Instant.now().plus(validity)))
        .claim("vct", sdJwt.getVcType())
        .claim("_sd_alg", sdJwt.getSdAlgorithm().getSdJwtName())
        .claim(
          "cnf",
          sdJwt.getConfirmationKey() != null
            ? Collections.singletonMap(
              "jwk",
              sdJwt.confirmationKey.toJSONObject()
            )
            : null
        )
        .claim("status", sdJwt.getStatus());

      ClaimsWithDisclosure cwd = sdJwt.getClaimsWithDisclosure();
      cwd
        .getAllSupportingClaims()
        .forEach(claimsBuilder::claim);
      // Create JWT
      final SignedJWT jwt = new SignedJWT(
        new JWSHeader.Builder(algorithm)
          .keyID(kid)
          .x509CertChain(
            List.of(
              Base64.encode(issuerCredential.getCertificate().getEncoded())
            )
          )
          .type(sdJwt.getJwtType())
          .build(),
        claimsBuilder.build()
      );
      jwt.sign(signer);
      sdJwt.setIssuerSigned(jwt);
      return sdJwt;
    }
  }

  /**
   * Parses a verifiable presentation to extract and initialize an SdJwt object.
   *
   * @param presentation a string representing the verifiable presentation, typically containing
   *                      multiple components separated by `~`, such as the SD-JWT and associated disclosures
   * @return an SdJwt object initialized with the parsed information.
   * @throws TokenValidationException if the provided presentation is null, improperly formatted, 
   *                                   or if parsing fails due to invalid data or processing errors.
   */
  public static SdJwt parse(String presentation)
    throws TokenValidationException {
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
      TokenDigestAlgorithm sdAlgo = TokenDigestAlgorithm.fromSdJwtName((String) claimsMap.get("_sd_alg"));
      sdJwt.setSdAlgorithm(sdAlgo);
      sdJwt.setIssuer(claimsSet.getIssuer());
      sdJwt.setSubject(claimsSet.getSubject());
      sdJwt.setStatus(claimsSet.getClaim("status"));
      sdJwt.setConfirmationKey(confirmationKey);
      STD_CLAIMS.forEach(claimsMap::remove);
      if (claimsMap.containsKey("_sd")) {
        sdJwt.setClaimsWithDisclosure(
          ClaimsWithDisclosure.parse(claimsMap, disclosureList, sdAlgo)
        );
      }

      return sdJwt;
    } catch (
      ParseException | JsonProcessingException | NoSuchAlgorithmException e
    ) {
      throw new TokenValidationException("Unable to parse token data", e);
    }
  }

  /**
   * Parses the confirmation key object to extract a JWK (JSON Web Key).
   *
   * @param cnf the confirmation key object, which can either be null or a map containing a "jwk" key with its value
   *            representing the JWK to be parsed
   * @return a JWK object parsed from the confirmation key, or null if the input is null
   * @throws TokenValidationException if the confirmation key format is invalid or does not contain a valid "jwk" entry
   * @throws ParseException if the JWK parsing fails
   */
  public static JWK parseConfirmationKey(Object cnf)
    throws TokenValidationException, ParseException {
    if (cnf == null) {
      return null;
    }
    if (cnf instanceof Map<?, ?> confirmationMap) {
      if (confirmationMap.get("jwk") instanceof Map<?, ?> jwkMap) {
        return JWK.parse((Map<String, Object>) jwkMap);
      } else {
        throw new TokenValidationException("No JWK key in cnf claim");
      }
    } else {
      throw new TokenValidationException("Invalid confirmation key format");
    }
  }
}

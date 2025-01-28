package se.digg.wallet.datatypes.sdjwt.process;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JOSEObjectType;
import com.nimbusds.jose.JWSVerifier;
import com.nimbusds.jose.Payload;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.util.Base64;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import se.digg.wallet.datatypes.common.*;
import se.digg.wallet.datatypes.sdjwt.JSONUtils;
import se.digg.wallet.datatypes.sdjwt.data.ClaimsWithDisclosure;
import se.digg.wallet.datatypes.sdjwt.data.Disclosure;
import se.digg.wallet.datatypes.sdjwt.data.SdJwt;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.text.ParseException;
import java.time.Duration;
import java.time.Instant;
import java.util.*;

/**
 * Description
 */
public class SdJwtTokenValidator implements TokenValidator {

  private final Duration timeSkew;

  public SdJwtTokenValidator(Duration timeSkew) {
    this.timeSkew = timeSkew;
  }

  public SdJwtTokenValidator() {
    this.timeSkew = Duration.ofSeconds(30);
  }

  @Override public SdJwtTokenValidationResult validateToken(byte[] token, List<TrustedKey> trustedKeys) throws TokenValidationException {
    try {
      SdJwt parsedToken = SdJwt.parse(new String(token, StandardCharsets.UTF_8));
      SignedJWT issuerSigned = parsedToken.getIssuerSigned();
      if (issuerSigned == null) {
        throw new TokenValidationException("Issuer signature missing");
      }
      // Check jwt type
      if (!issuerSigned.getHeader().getType().equals(new JOSEObjectType(SdJwt.SD_JWT_TYPE))) {
        throw new TokenValidationException("Illegal JWT type for SD JWT: " +  issuerSigned.getHeader().getType());
      }

      // Retrieve certificate chain in signature and determine trusted signing key
      List<Base64> x5chain = issuerSigned.getHeader().getX509CertChain();
      String kid = issuerSigned.getHeader().getKeyID();
      List<X509Certificate> chain = getChain(x5chain);
      // Get the trusted validation key. If trustedKeys is null, then all keys are trusted
      PublicKey validationKey = getValidationKey(chain, kid, trustedKeys);
      if (validationKey == null) {
        throw new TokenValidationException("No validation key was found");
      }
      TokenSigningAlgorithm algorithm = TokenSigningAlgorithm.fromJWSAlgorithm(issuerSigned.getHeader().getAlgorithm());
      JWSVerifier jwsVerifier = algorithm.jwsVerifier(validationKey);
      if (!issuerSigned.verify(jwsVerifier)) {
        throw new TokenValidationException("Token signature validation failed");
      }
      JWTClaimsSet issuerSignedClaims = issuerSigned.getJWTClaimsSet();
      timeValidation(issuerSignedClaims);
      PublicKey walletPublic = getWalletPublic(issuerSignedClaims);
      boolean hasKeyBindingProof = validateKeyBinding(walletPublic, parsedToken);

      Payload reconstructedPayload = restorePayload(parsedToken);

      SdJwtTokenValidationResult result = new SdJwtTokenValidationResult();
      result.setVcToken(parsedToken);
      result.setDisclosedTokenPayload(reconstructedPayload);
      result.setKeyBindingProtection(hasKeyBindingProof);
      result.setValidationKey(validationKey);
      result.setValidationChain(chain);
      result.setValidationCertificate(chain.isEmpty() ? null : chain.getFirst());
      result.setWalletPublicKey(walletPublic);
      return result;

    }
    catch (CertificateException | IOException | NoSuchAlgorithmException | JOSEException | ParseException e) {
      throw new RuntimeException(e);
    }
  }

  private Payload restorePayload(SdJwt parsedToken) throws ParseException, NoSuchAlgorithmException {

    ClaimsWithDisclosure claimsWithDisclosure = parsedToken.getClaimsWithDisclosure();
    Map<String, Object> claims = new HashMap<>(parsedToken.getIssuerSigned().getJWTClaimsSet().getClaims());
    String hashAlgo = (String) claims.get("_sd_alg");
    expandClaims(claims, claimsWithDisclosure.getAllDisclosures(), hashAlgo);
    Payload reconstructedPayload = new Payload(claims);
    return reconstructedPayload;
  }

  private void expandClaims(Map<String, Object> claims, List<Disclosure> allDisclosures, String hashAlgo) throws NoSuchAlgorithmException {
    // First task. Look for child with "_sd" declarations.
    Map<String, Object> dataClaims = new HashMap<>(claims);
    SdJwt.STD_CLAIMS.forEach(dataClaims::remove);
    for (Map.Entry<String, Object> entry: dataClaims.entrySet()) {
      if (entry.getValue() instanceof Map<?,?> subMap) {
        if (subMap.containsKey("_sd")) {
          expandClaims((Map<String, Object>) entry.getValue(), allDisclosures, hashAlgo);
        }
      }
    }
    // Now look at this base level and expand new items on the base level.
    if (!claims.containsKey("_sd")){
      return;
    }
    // Start with List items
    for (Map.Entry<String, Object> entry : claims.entrySet()) {
      if (entry.getValue() instanceof List<?> && !entry.getKey().equals("_sd")) {
        List<?> list = (List<?>) entry.getValue();
        List<Object> expandedList = new ArrayList<>();
        for (Object item : list) {
          if (item instanceof Map<?, ?>) {
            // This is a map possibly containing a selective disclosure value.
            if (((Map<?, ?>) item).containsKey("...")){
              // We found a selective disclosure lite item value
              Disclosure matchingDisclosure = getMatchingDisclosure((String)((Map<?, ?>) item).get("..."), allDisclosures, hashAlgo);
              if (matchingDisclosure != null) {
                // We found a matching disclosure. Use its value
                expandedList.add(matchingDisclosure.getValue());
              }
            }
          }
          else {
            // This was not a Map item. Keep the original value
            expandedList.add(item);
          }
        }
        // Store the updated values
        entry.setValue(expandedList);
      }
    }
    // And finally, add new MAP items.
    List<String> sdClaims = (List<String>) claims.get("_sd");
    // sdClaims holds all hashes of potential claims on this level
    for (Disclosure disclosure : allDisclosures) {
      // Iterating through all disclosures relevant to test
      String hashString = JSONUtils.disclosureHashString(disclosure, hashAlgo);
      // Getting the hash string for each disclosure
      if (sdClaims.contains(hashString)) {
        // This disclosure is matched against a signed sd_hash
        if (disclosure.getName() != null) {
          // There is a complete name value pair in the disclosure. Add this to value map
          claims.put(disclosure.getName(), disclosure.getValue());
        }
      }
    }
    claims.remove("_sd");
  }

  private Disclosure getMatchingDisclosure(String b64UrlHash, List<Disclosure> allDisclosures, String hashAlgo)
    throws NoSuchAlgorithmException {
    for (Disclosure disclosure : allDisclosures) {
      String hashString = JSONUtils.disclosureHashString(disclosure, hashAlgo);
      if (b64UrlHash.equals(hashString)) {
        return disclosure;
      }
    }
    return null;
  }

  /**
   * Validates the key binding by verifying the wallet signature and comparing the hash. If no key binding is available
   * a false value is returned.
   * If a key binding is available but fails validation, an exception is thrown.
   *
   * @param walletPublic The public key of the wallet to validate against.
   * @param parsedToken The parsed security token containing the signed data and claims.
   * @return true if the key binding is valid, false if there is no key binding to validate.
   * @throws NoSuchAlgorithmException If a required cryptographic algorithm is not available.
   * @throws JOSEException If an error occurs during JWS processing.
   * @throws TokenValidationException If the token validation fails.
   * @throws ParseException If the parsing of the signed data fails.
   */
  private boolean validateKeyBinding(PublicKey walletPublic, SdJwt parsedToken)
    throws NoSuchAlgorithmException, JOSEException, TokenValidationException, ParseException {
    SignedJWT walletSigned = parsedToken.getWalletSigned();
    if (walletSigned == null) {
      // There is no wallet signature to validate
      return false;
    }
    // Check jwt type
    if (!walletSigned.getHeader().getType().equals(new JOSEObjectType(SdJwt.KB_JWT_TYPE))) {
      throw new TokenValidationException("Illegal JWT type for SD JWT: " +  walletSigned.getHeader().getType());
    }

    TokenSigningAlgorithm algorithm = TokenSigningAlgorithm.fromJWSAlgorithm(walletSigned.getHeader().getAlgorithm());
    JWSVerifier walletVerifier = algorithm.jwsVerifier(walletPublic);
    if (!walletSigned.verify(walletVerifier)) {
      throw new TokenValidationException("Wallet signature validation failed");
    }
    String sdHash = (String) walletSigned.getJWTClaimsSet().getClaim("sd_hash");
    String unprotectedPresentation = parsedToken.unprotectedPresentation(null);
    MessageDigest messageDigest = MessageDigest.getInstance(algorithm.getDigestAlgorithm().getJdkName());
    String digestStr = JSONUtils.b64UrlHash(unprotectedPresentation.getBytes(StandardCharsets.UTF_8), algorithm.getDigestAlgorithm().getJdkName());
    if (!digestStr.equals(sdHash)) {
      throw new TokenValidationException("Hash mismatch between signed data and key binding JWT");
    }
    return true;
  }

  private PublicKey getWalletPublic(JWTClaimsSet issuerSignedClaims) throws TokenValidationException {
    try {
      JWK walletPublic = Optional.ofNullable(SdJwt.parseConfirmationKey(issuerSignedClaims.getClaim("cnf"))).orElseThrow(() ->
        new TokenValidationException("No wallet public key found in token"));
      return JSONUtils.getPublicKeyFromJWK(walletPublic);
    }
    catch (ParseException | JOSEException e) {
      throw new TokenValidationException("Failed to parse wallet public key", e);
    }
  }

  private void timeValidation(JWTClaimsSet jwtClaimsSet) throws TokenValidationException {
    Instant issueTime = Optional.ofNullable(jwtClaimsSet.getIssueTime().toInstant()).orElseThrow(
      () -> new TokenValidationException("Issue time is not declared"));
    Instant notBefore = Optional.ofNullable(jwtClaimsSet.getNotBeforeTime())
      .orElse(Date.from(Instant.now().minus(Duration.ofDays(1)))).toInstant();
    Instant expirationTime = Optional.ofNullable(jwtClaimsSet.getExpirationTime().toInstant()).orElseThrow(
      () -> new TokenValidationException("Expiration time is not declared"));
    Instant currentTime = Instant.now();
    if (currentTime.isBefore(issueTime.minus(timeSkew))) {
      throw new TokenValidationException("Token declares issue time in the future");
    }
    if (currentTime.isBefore(notBefore.minus(timeSkew))) {
      throw new TokenValidationException("Token is not yet valid");
    }
    if (currentTime.isAfter(expirationTime.plus(timeSkew))) {
      throw new TokenValidationException("Token has expired");
    }
  }

  private PublicKey getValidationKey(List<X509Certificate> chain, String kid, List<TrustedKey> trustedKeys)
    throws TokenValidationException {
    boolean allTrusted = trustedKeys == null;
    PublicKey providedKey = chain.isEmpty() ? null : chain.getFirst().getPublicKey();
    if (!allTrusted) {
      for (TrustedKey trustedKey : trustedKeys) {
        PublicKey trustedPublicKey = Optional.ofNullable(trustedKey.getPublicKey()).orElse(trustedKey.getCertificate().getPublicKey());
        if (providedKey != null && providedKey.equals(trustedPublicKey)) {
          return providedKey;
        }
        if (trustedKey.getKeyId() != null && trustedKey.getKeyId().equals(kid)) {
          return trustedPublicKey;
        }
      }
      throw new TokenValidationException("Trusted keys was provided, but none matched the signing key");
    } else {
      // All keys are trusted. Return the provided signing key
      return providedKey;
    }

  }

  private List<X509Certificate> getChain(List<Base64> x5chain) throws IOException, CertificateException {
    List<X509Certificate> chain = new ArrayList<>();
    if (x5chain == null) {
      return chain;
    }
    for (Base64 cert : x5chain) {
      byte[] decodedCert = cert.decode();
      try (InputStream is = new ByteArrayInputStream(decodedCert))  {
        CertificateFactory cf = CertificateFactory.getInstance("X.509");
        X509Certificate x509Cert = (X509Certificate) cf.generateCertificate(is);
        chain.add(x509Cert);
      }
    }
    return chain;
  }
}

// SPDX-FileCopyrightText: 2024 Digg - Agency for Digital Government
//
// SPDX-License-Identifier: EUPL-1.2

package se.digg.wallet.datatypes.sdjwt.process;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JOSEObjectType;
import com.nimbusds.jose.JWSVerifier;
import com.nimbusds.jose.Payload;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.util.Base64;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
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
import java.util.ArrayList;
import java.util.Date;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import lombok.Setter;
import se.digg.wallet.datatypes.common.TokenSigningAlgorithm;
import se.digg.wallet.datatypes.common.TokenValidationException;
import se.digg.wallet.datatypes.common.TokenValidator;
import se.digg.wallet.datatypes.common.TrustedKey;
import se.digg.wallet.datatypes.common.Utils;
import se.digg.wallet.datatypes.sdjwt.JSONUtils;
import se.digg.wallet.datatypes.sdjwt.data.ClaimsWithDisclosure;
import se.digg.wallet.datatypes.sdjwt.data.Disclosure;
import se.digg.wallet.datatypes.sdjwt.data.SdJwt;

/**
 * The SdJwtTokenValidator class is responsible for the validation of SD-JWT tokens. It implements the
 * {@code TokenValidator} interface and provides functionality to parse, verify, and validate tokens
 * following the SD-JWT specification, including the reconstruction of selective disclosure claims,
 * time-based validations, key binding proof verification, and certificate chain validation.
 */
@SuppressWarnings("PMD.CollapsibleIfStatements")
public class SdJwtTokenValidator implements TokenValidator {

  /** Max allowed time skew */
  private final Duration timeSkew;

  /** Valid SD JWT header typ values */
  @Setter
  private List<JOSEObjectType> validSdJweHeaderTypes = List.of(
    SdJwt.SD_JWT_TYPE,
    SdJwt.SD_JWT_TYPE_LEGACY
  );

  /**
   * Constructs an SdJwtTokenValidator with a specified time skew.
   *
   * @param timeSkew The accepted time skew duration for token validation to account for clock differences.
   */
  public SdJwtTokenValidator(Duration timeSkew) {
    this.timeSkew = timeSkew;
  }

  /**
   * Default constructor for the SdJwtTokenValidator class.
   * Initializes the validator with a default time skew of 30 seconds.
   * The time skew is used to account for clock differences during token validation.
   */
  public SdJwtTokenValidator() {
    this.timeSkew = Duration.ofSeconds(30);
  }

  /**
   * Validates an SD-JWT token against provided trusted keys and internal rules.
   * Performs signature verification, time validation, key binding validation,
   * and payload restoration.
   *
   * @param token The SD-JWT token as a byte array.
   * @param trustedKeys A list of optional trusted keys to validate the token against. May be null to trust all keys.
   * @return An instance of {@code SdJwtTokenValidationResult} that contains
   *         the details of the validated token and any extracted data.
   * @throws TokenValidationException If token validation fails due to invalid signature, expired token,
   *                                   untrusted signing certificate, or violation of key binding mechanisms.
   */
  @Override
  public SdJwtTokenValidationResult validateToken(
    byte[] token,
    List<TrustedKey> trustedKeys
  ) throws TokenValidationException {
    try {
      SdJwt parsedToken = SdJwt.parse(
        new String(token, StandardCharsets.UTF_8)
      );
      SignedJWT issuerSigned = parsedToken.getIssuerSigned();
      if (issuerSigned == null) {
        throw new TokenValidationException("Issuer signature missing");
      }
      // Check jwt type
      JOSEObjectType type = issuerSigned.getHeader().getType();
      if (!validSdJweHeaderTypes.contains(type)) {
        throw new TokenValidationException(
          "Illegal JWT type for SD JWT: " + type
        );
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
      TokenSigningAlgorithm algorithm = TokenSigningAlgorithm.fromJWSAlgorithm(
        issuerSigned.getHeader().getAlgorithm()
      );
      JWSVerifier jwsVerifier = algorithm.jwsVerifier(validationKey);
      if (!issuerSigned.verify(jwsVerifier)) {
        throw new TokenValidationException("Token signature validation failed");
      }
      JWTClaimsSet issuerSignedClaims = issuerSigned.getJWTClaimsSet();
      timeValidation(issuerSignedClaims);
      PublicKey walletPublic = getWalletPublic(issuerSignedClaims);
      boolean hasKeyBindingProof = validateKeyBinding(
        walletPublic,
        parsedToken
      );

      Payload reconstructedPayload = restorePayload(parsedToken);

      SdJwtTokenValidationResult result = new SdJwtTokenValidationResult();
      result.setIssueTime(issuerSignedClaims.getIssueTime().toInstant());
      result.setExpirationTime(
        issuerSignedClaims.getExpirationTime().toInstant()
      );
      result.setVcToken(parsedToken);
      result.setDisclosedTokenPayload(reconstructedPayload);
      result.setKeyBindingProtection(hasKeyBindingProof);
      result.setValidationKey(validationKey);
      result.setValidationChain(chain);
      result.setValidationCertificate(
        chain.isEmpty() ? null : chain.getFirst()
      );
      result.setWalletPublicKey(walletPublic);
      if (hasKeyBindingProof) {
        result.setPresentationRequestNonce(
          (String) parsedToken
            .getWalletSigned()
            .getJWTClaimsSet()
            .getClaim("nonce")
        );
        result.setAudience(
          parsedToken.getWalletSigned().getJWTClaimsSet().getAudience()
        );
      }

      return result;
    } catch (
      CertificateException
      | IOException
      | NoSuchAlgorithmException
      | JOSEException
      | ParseException e
    ) {
      throw new RuntimeException(e);
    }
  }

  /**
   * Restores the disclosed payload of an SD-JWT token by processing its claims and disclosures.
   *
   * @param parsedToken The parsed SD-JWT token containing the signed claims and disclosures.
   * @return A {@code Payload} object containing the restored claims after processing.
   * @throws ParseException If the claims or disclosures cannot be parsed.
   * @throws NoSuchAlgorithmException If the specified hash algorithm is not available.
   */
  private Payload restorePayload(SdJwt parsedToken)
    throws ParseException, NoSuchAlgorithmException {
    ClaimsWithDisclosure claimsWithDisclosure =
      parsedToken.getClaimsWithDisclosure();
    Map<String, Object> claims = new HashMap<>(
      parsedToken.getIssuerSigned().getJWTClaimsSet().getClaims()
    );
    String hashAlgo = (String) claims.get("_sd_alg");
    expandClaims(claims, claimsWithDisclosure.getAllDisclosures(), hashAlgo);
    return new Payload(claims);
  }

  /**
   * Expands the claims in a map by resolving selective disclosure fields and integrating matching disclosures.
   * The method processes nested claim structures and iteratively replaces selective disclosure references
   * with their corresponding values from a list of provided disclosures.
   *
   * @param claims a map containing the original claims of the token which
   *               may include selective disclosure references that need to be resolved
   * @param allDisclosures a list of Disclosure objects representing the available
   *                       disclosures from which values can be extracted
   * @param hashAlgo the hash algorithm used to compute and validate the selective disclosure hashes
   * @throws NoSuchAlgorithmException if the specified hash algorithm is not supported
   */
  private void expandClaims(
    Map<String, Object> claims,
    List<Disclosure> allDisclosures,
    String hashAlgo
  ) throws NoSuchAlgorithmException {
    // First task. Look for child with "_sd" declarations.
    Map<String, Object> dataClaims = new HashMap<>(claims);
    SdJwt.STD_CLAIMS.forEach(dataClaims::remove);
    for (Map.Entry<String, Object> entry : dataClaims.entrySet()) {
      if (entry.getValue() instanceof Map<?, ?> subMap) {
        if (subMap.containsKey("_sd")) {
          expandClaims(
            Utils.ensureStringObjectMap(entry.getValue()),
            allDisclosures,
            hashAlgo
          );
        }
      }
    }
    // Now look at this base level and expand new items on the base level.
    if (!claims.containsKey("_sd")) {
      return;
    }
    // Start with List items
    for (Map.Entry<String, Object> entry : claims.entrySet()) {
      if (
        entry.getValue() instanceof List<?> list &&
        !entry.getKey().equals("_sd")
      ) {
        List<Object> expandedList = new ArrayList<>();
        for (Object item : list) {
          if (item instanceof Map<?, ?>) {
            // This is a map possibly containing a selective disclosure value.
            if (((Map<?, ?>) item).containsKey("...")) {
              // We found a selective disclosure lite item value
              Disclosure matchingDisclosure = getMatchingDisclosure(
                (String) ((Map<?, ?>) item).get("..."),
                allDisclosures,
                hashAlgo
              );
              if (matchingDisclosure != null) {
                // We found a matching disclosure. Use its value
                expandedList.add(matchingDisclosure.getValue());
              }
            }
          } else {
            // This was not a Map item. Keep the original value
            expandedList.add(item);
          }
        }
        // Store the updated values
        entry.setValue(expandedList);
      }
    }
    // And finally, add new MAP items.
    List<String> sdClaims = Utils.ensureStringList(claims.get("_sd"));
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

  /**
   * Finds and returns a matching {@code Disclosure} instance from a list of disclosures based on
   * a base64 URL-encoded hash value and a specified hash algorithm. If no matching disclosure is
   * found, the method returns {@code null}.
   *
   * @param b64UrlHash the base64 URL-encoded hash value to find a matching disclosure for
   * @param allDisclosures a list of {@code Disclosure} objects to search through
   * @param hashAlgo the hash algorithm used for computing and comparing the hash values
   * @return the matching {@code Disclosure} instance if found, {@code null} otherwise
   * @throws NoSuchAlgorithmException if the specified hash algorithm is not available
   */
  private Disclosure getMatchingDisclosure(
    String b64UrlHash,
    List<Disclosure> allDisclosures,
    String hashAlgo
  ) throws NoSuchAlgorithmException {
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
    JOSEObjectType type = walletSigned.getHeader().getType();
    if (!type.equals(SdJwt.KB_JWT_TYPE)) {
      throw new TokenValidationException(
        "Illegal JWT type for SD JWT: " + type
      );
    }

    TokenSigningAlgorithm algorithm = TokenSigningAlgorithm.fromJWSAlgorithm(
      walletSigned.getHeader().getAlgorithm()
    );
    JWSVerifier walletVerifier = algorithm.jwsVerifier(walletPublic);
    if (!walletSigned.verify(walletVerifier)) {
      throw new TokenValidationException("Wallet signature validation failed");
    }
    String sdHash = (String) walletSigned.getJWTClaimsSet().getClaim("sd_hash");
    String unprotectedPresentation = parsedToken.unprotectedPresentation(null);
    MessageDigest.getInstance(algorithm.getDigestAlgorithm().getJdkName());
    String digestStr = JSONUtils.b64UrlHash(
      unprotectedPresentation.getBytes(StandardCharsets.UTF_8),
      algorithm.getDigestAlgorithm().getJdkName()
    );
    if (!digestStr.equals(sdHash)) {
      throw new TokenValidationException(
        "Hash mismatch between signed data and key binding JWT"
      );
    }
    return true;
  }

  /**
   * Retrieves the public key of the wallet from the provided issuer-signed claims.
   *
   * @param issuerSignedClaims The JWT claims set signed by the issuer containing
   *                           the wallet public key information.
   * @return The wallet's {@code PublicKey} extracted and parsed from the claims.
   * @throws TokenValidationException If no wallet public key is found or if an
   *                                  error occurs during parsing of the wallet public key.
   */
  private PublicKey getWalletPublic(JWTClaimsSet issuerSignedClaims)
    throws TokenValidationException {
    try {
      JWK walletPublic = Optional.ofNullable(
        SdJwt.parseConfirmationKey(issuerSignedClaims.getClaim("cnf"))
      ).orElseThrow(
        () ->
          new TokenValidationException("No wallet public key found in token")
      );
      return JSONUtils.getPublicKeyFromJWK(walletPublic);
    } catch (ParseException | JOSEException e) {
      throw new TokenValidationException(
        "Failed to parse wallet public key",
        e
      );
    }
  }

  /**
   * Validates the time-related claims of a JWT to ensure the token is within its valid time window.
   * This includes checking the issue time, not-before time, and expiration time of the token.
   *
   * @param jwtClaimsSet The JWT claims set containing the time-based claims such as issue time,
   *                     not-before time, and expiration time.
   * @throws TokenValidationException If the token's issue time or expiration time is missing,
   *                                  or if the current time is outside the valid time window.
   */
  private void timeValidation(JWTClaimsSet jwtClaimsSet)
    throws TokenValidationException {
    Instant issueTime = Optional.ofNullable(
      jwtClaimsSet.getIssueTime().toInstant()
    ).orElseThrow(
      () -> new TokenValidationException("Issue time is not declared")
    );
    Instant notBefore = Optional.ofNullable(jwtClaimsSet.getNotBeforeTime())
      .orElse(Date.from(Instant.now().minus(Duration.ofDays(1))))
      .toInstant();
    Instant expirationTime = Optional.ofNullable(
      jwtClaimsSet.getExpirationTime().toInstant()
    ).orElseThrow(
      () -> new TokenValidationException("Expiration time is not declared")
    );
    Instant currentTime = Instant.now();
    if (currentTime.isBefore(issueTime.minus(timeSkew))) {
      throw new TokenValidationException(
        "Token declares issue time in the future"
      );
    }
    if (currentTime.isBefore(notBefore.minus(timeSkew))) {
      throw new TokenValidationException("Token is not yet valid");
    }
    if (currentTime.isAfter(expirationTime.plus(timeSkew))) {
      throw new TokenValidationException("Token has expired");
    }
  }

  /**
   * Retrieves the public key used to validate a token by determining whether the provided
   * key in the certificate chain matches any of the trusted keys or key IDs.
   *
   * @param chain A list of X509 certificate chain whose public key may be used for validation.
   *              If the chain is empty, no public key is provided.
   * @param kid The key identifier (key ID) associated with the token for which validation is being performed.
   *            This is used to locate a matching trusted key.
   * @param trustedKeys A list of trusted keys to validate the provided key against. If null, all keys are
   *                    considered as trusted.
   * @return The public key to be used for validation if the provided key matches a trusted key or key ID.
   * @throws TokenValidationException If no matching trusted key is found and trusted keys were explicitly provided.
   */
  private PublicKey getValidationKey(
    List<X509Certificate> chain,
    String kid,
    List<TrustedKey> trustedKeys
  ) throws TokenValidationException {
    boolean allTrusted = trustedKeys == null;
    PublicKey providedKey = chain.isEmpty()
      ? null
      : chain.getFirst().getPublicKey();
    if (!allTrusted) {
      for (TrustedKey trustedKey : trustedKeys) {
        PublicKey trustedPublicKey = Optional.ofNullable(
          trustedKey.getPublicKey()
        ).orElse(trustedKey.getCertificate().getPublicKey());
        if (providedKey != null && providedKey.equals(trustedPublicKey)) {
          return providedKey;
        }
        if (
          trustedKey.getKeyId() != null && trustedKey.getKeyId().equals(kid)
        ) {
          return trustedPublicKey;
        }
      }
      throw new TokenValidationException(
        "Trusted keys was provided, but none matched the signing key"
      );
    } else {
      // All keys are trusted. Return the provided signing key
      return providedKey;
    }
  }

  /**
   * Converts a list of Base64-encoded certificates into a list of X509Certificate objects.
   * Decodes each Base64 entry, parses the certificate data, and constructs the corresponding X509Certificate.
   * If the input list is null, an empty list is returned.
   *
   * @param x5chain a list of Base64-encoded certificates. May be null or empty
   * @return a list of X509Certificate objects representing the decoded and parsed certificates
   * @throws IOException if an I/O error occurs during certificate stream processing
   * @throws CertificateException if the certificate parsing or validation fails
   */
  private List<X509Certificate> getChain(List<Base64> x5chain)
    throws IOException, CertificateException {
    List<X509Certificate> chain = new ArrayList<>();
    if (x5chain == null) {
      return chain;
    }
    for (Base64 cert : x5chain) {
      byte[] decodedCert = cert.decode();
      try (InputStream is = new ByteArrayInputStream(decodedCert)) {
        CertificateFactory cf = CertificateFactory.getInstance("X.509");
        X509Certificate x509Cert = (X509Certificate) cf.generateCertificate(is);
        chain.add(x509Cert);
      }
    }
    return chain;
  }
}

// SPDX-FileCopyrightText: 2024 Digg - Agency for Digital Government
//
// SPDX-License-Identifier: EUPL-1.2

package se.digg.wallet.datatypes.mdl.process;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.upokecenter.cbor.CBORException;
import com.upokecenter.cbor.CBORObject;
import com.upokecenter.cbor.CBORType;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.time.Duration;
import java.time.Instant;
import java.util.*;
import se.digg.wallet.datatypes.common.*;
import se.digg.wallet.datatypes.mdl.data.*;
import se.idsec.cose.*;

/**
 * Validator for validating @{link {@link IssuerSigned} tokens.
 * The IssuerSigned element is the Issuer provided part of a EUDI wallet mDL token.
 * This is then completed in the Wallet to produce a complete verifiable credential presentation in the form of a mDoc
 *
 * <p>
 *   The user attributes in the IssuerSigned object is not masked, but individually signed by the signature.
 *   Selective disclosure is achieved by deleting the attributes that should not be revealed from this token.
 *   This then does not break the signature.
 * </p>
 *
 * <p>
 *   Validation of an IssuerSigned token includes the following steps.
 * </p>
 *
 * <ul>
 *   <li>Key validation if a list of trusted keys is provided. Otherwise testing is a key is provided and validates the signature</li>
 *   <li>Checking issue date and validity</li>
 *   <li>Validating the signature</li>
 *   <li>Validating the signed hash of all present attributes. (This works also if some attributes are deleted)</li>
 * </ul>
 */
public class MdlIssuerSignedValidator implements TokenValidator {

  private final Duration timeSkew;

  /**
   * Initializes a new instance of the MdlIssuerSignedValidator class with a specified time skew.
   *
   * @param timeSkew the duration representing the time difference allowed between the client and server in verifying tokens.
   */
  public MdlIssuerSignedValidator(Duration timeSkew) {
    this.timeSkew = timeSkew;
  }

  /**
   * Initializes a new instance of the MdlIssuerSignedValidator class with a default time skew of 30 seconds.
   */
  public MdlIssuerSignedValidator() {
    this.timeSkew = Duration.ofSeconds(30);
  }

  /**
   * Validates an IssuerSigned token issued by a EUDI wallet PID issuer or attestation issuer
   *
   * @param token the CBOR encoded token to be validated as a byte array.
   * @param trustedKeys optional list of trusted keys used for validation.
   * @return TokenValidationResult containing information about the validated token
   * @throws TokenValidationException if there are any failures during the token validation process
   */
  @Override
  public MdlIssuerSignedValidationResult validateToken(
    byte[] token,
    List<TrustedKey> trustedKeys
  ) throws TokenValidationException {
    try {
      IssuerSigned parsedIssuerSigned = IssuerSigned.deserialize(token);
      Sign1COSEObject parsedSignatureObject =
        (Sign1COSEObject) Sign1COSEObject.DecodeFromBytes(
          parsedIssuerSigned.getIssuerAuth(),
          COSEObjectTag.Sign1
        );
      CBORObject unprotectedAttributes =
        parsedSignatureObject.getUnprotectedAttributes();

      // Retrieve certificate chain in signature and determine trusted signing key
      CBORObject x5chain = unprotectedAttributes.get(
        HeaderKeys.x5chain.AsCBOR()
      );
      List<X509Certificate> chain = getChain(x5chain);
      // Get the trusted validation key. If trustedKeys is null, then all keys are trusted
      PublicKey validationKey = getValidationKey(
        chain,
        parsedSignatureObject,
        trustedKeys
      );
      if (validationKey == null) {
        throw new TokenValidationException("No validation key was found");
      }
      if (!parsedSignatureObject.validate(new COSEKey(validationKey, null))) {
        throw new TokenValidationException("Token signature validation failed");
      }

      MobileSecurityObject mso = MobileSecurityObject.deserialize(
        parsedSignatureObject.GetContent()
      );
      // Validate time
      timeValidation(mso);
      // Retrieve the wallet public key
      MobileSecurityObject.DeviceKeyInfo deviceKeyInfo = mso.getDeviceKeyInfo();
      PublicKey walletPublicKey = null;
      if (deviceKeyInfo != null) {
        walletPublicKey = deviceKeyInfo.getDeviceKey().AsPublicKey();
      }
      // Validate signatures on all present attributes
      validateAttributes(parsedIssuerSigned.getNameSpaces(), mso, token);

      // Construct the validation result
      MdlIssuerSignedValidationResult validationResult =
        new MdlIssuerSignedValidationResult();
      validationResult.setIssueTime(mso.getValidityInfo().getValidFrom());
      validationResult.setExpirationTime(mso.getValidityInfo().getValidUntil());
      validationResult.setValidationChain(chain);
      validationResult.setValidationCertificate(
        chain.isEmpty() ? null : chain.getFirst()
      );
      validationResult.setValidationKey(validationKey);
      validationResult.setIssuerSigned(parsedIssuerSigned);
      validationResult.setWalletPublicKey(walletPublicKey);
      validationResult.setMso(mso);
      return validationResult;
    } catch (JsonProcessingException e) {
      throw new TokenValidationException(
        "Failed to parse Issuer Signed token",
        e
      );
    } catch (TokenParsingException e) {
      throw new TokenValidationException(
        "Failed to validate Issuer Signed token",
        e
      );
    } catch (CoseException e) {
      throw new TokenValidationException(
        "Token signature validation failure",
        e
      );
    } catch (CertificateException e) {
      throw new TokenValidationException(
        "Error processing signature certificate information",
        e
      );
    } catch (NoSuchAlgorithmException e) {
      throw new TokenValidationException("Unsupported Hash algorithm", e);
    } catch (IOException e) {
      throw new TokenValidationException("Error parsing input data", e);
    }
  }

  /**
   * Validates the time validity of a MobileSecurityObject.
   *
   * @param mso the MobileSecurityObject to validate
   * @throws TokenValidationException if the MobileSecurityObject does not contain validity information,
   * the signing time is not declared, the valid from time is not declared, the expiration time is not declared,
   * the token declares signing time in the future, the token is not yet valid, or the token has expired
   */
  private void timeValidation(MobileSecurityObject mso)
    throws TokenValidationException {
    MobileSecurityObject.ValidityInfo validityInfo = mso.getValidityInfo();
    if (validityInfo == null) {
      throw new TokenValidationException(
        "MobileSecurityObject does not contain validity information"
      );
    }
    Instant signingTime = Optional.ofNullable(
      validityInfo.getSigned()
    ).orElseThrow(
      () -> new TokenValidationException("Signing time is not declared")
    );
    Instant validFrom = Optional.ofNullable(
      validityInfo.getValidFrom()
    ).orElseThrow(
      () -> new TokenValidationException("Valid from time is not declared")
    );
    Instant expirationTime = Optional.ofNullable(
      validityInfo.getValidUntil()
    ).orElseThrow(
      () -> new TokenValidationException("Expiration time is not declared")
    );
    Instant currentTime = Instant.now();
    if (currentTime.isBefore(signingTime.minus(timeSkew))) {
      throw new TokenValidationException(
        "Token declares signing time in the future"
      );
    }
    if (currentTime.isBefore(validFrom.minus(timeSkew))) {
      throw new TokenValidationException("Token is not yet valid");
    }
    if (currentTime.isAfter(expirationTime.plus(timeSkew))) {
      throw new TokenValidationException("Token has expired");
    }
  }

  /**
   * Validates the attributes of a MobileSecurityObject against a map of namespaces and signed items.
   *
   * @param nameSpaces a map containing namespace strings as keys and lists of IssuerSignedItems as values
   * @param mso the MobileSecurityObject to validate the attributes against
   * @throws TokenValidationException if there are validation errors during attribute validation
   * @throws IOException if an I/O error occurs
   * @throws NoSuchAlgorithmException if a required cryptographic algorithm is not available
   */
  private void validateAttributes(
    Map<String, List<IssuerSignedItem>> nameSpaces,
    MobileSecurityObject mso,
    byte[] token
  ) throws TokenValidationException, NoSuchAlgorithmException {
    if (nameSpaces == null) {
      throw new TokenValidationException("Token has no attribute information");
    }
    Map<String, Map<Integer, byte[]>> tokenParsedIssuerSignedItemBytes =
      parseTokenIssuerSignedItems(token);
    for (Map.Entry<
      String,
      List<IssuerSignedItem>
    > entry : nameSpaces.entrySet()) {
      String namespace = entry.getKey();
      Map<Integer, byte[]> tokenParsedNameSpace =
        tokenParsedIssuerSignedItemBytes.get(namespace);
      List<IssuerSignedItem> items = entry.getValue();
      for (IssuerSignedItem item : items) {
        byte[] hashedBytes = tokenParsedNameSpace.get(item.getDigestID());
        MessageDigest digest = MessageDigest.getInstance(
          TokenDigestAlgorithm.fromMdlName(
            mso.getDigestAlgorithm()
          ).getJdkName()
        );
        byte[] signedItemHash = digest.digest(hashedBytes);
        byte[] msoHash = getMsoHash(
          mso.getValueDigests(),
          namespace,
          item.getDigestID()
        );
        if (msoHash == null) {
          throw new TokenValidationException(
            "No hash available for present attribute " +
            item.getDigestID() +
            "for name space " +
            namespace
          );
        }
        if (!Arrays.equals(signedItemHash, msoHash)) {
          throw new TokenValidationException(
            "Hash mismatch for attribute " +
            item.getDigestID() +
            " in namespace " +
            namespace
          );
        }
      }
    }
  }

  private Map<String, Map<Integer, byte[]>> parseTokenIssuerSignedItems(
    byte[] token
  ) throws TokenValidationException {
    try {
      Map<String, Map<Integer, byte[]>> valueDigests = new HashMap<>();
      CBORObject issuerSigned = CBORObject.DecodeFromBytes(token);
      CBORObject namespaces = issuerSigned.get("nameSpaces");
      List<CBORObject> nameSpaceList = namespaces.getKeys().stream().toList();
      for (CBORObject nameSpaceName : nameSpaceList) {
        CBORObject nameSpace = namespaces.get(nameSpaceName);
        for (int i = 0; i < nameSpace.size(); i++) {
          CBORObject issuerSignedItem = nameSpace.get(i);
          byte[] toBeHashedBytes = issuerSignedItem.EncodeToBytes();
          IssuerSignedItem itemObject = CBORUtils.CBOR_MAPPER.readValue(
            toBeHashedBytes,
            IssuerSignedItem.class
          );
          int digestID = itemObject.getDigestID();
          valueDigests
            .computeIfAbsent(nameSpaceName.AsString(), k -> new HashMap<>())
            .put(digestID, toBeHashedBytes);
        }
      }
      return valueDigests;
    } catch (CBORException e) {
      throw new TokenValidationException(
        "Failed to parse Issuer Signed Items",
        e
      );
    } catch (IOException e) {
      throw new TokenValidationException(
        "Unable to parse Issuer Signed Item bytes to object",
        e
      );
    }
  }

  /**
   * Retrieves the hash value corresponding to a given name space and digest ID from the provided value digests map.
   *
   * @param valueDigests a map containing signed hash values over provided attributes
   * @param nameSpace the provided user attributes under defined name spaces
   * @param digestID the ID of the signed digest for which the hash value is requested
   * @return the byte array representing the hash value, or null if the value digests map is null, the nameSpace is not found,
   * or the digest ID is not found within the specified nameSpace
   */
  private byte[] getMsoHash(
    Map<String, Map<Integer, byte[]>> valueDigests,
    String nameSpace,
    int digestID
  ) {
    if (valueDigests == null) {
      return null;
    }
    Map<Integer, byte[]> namespaceDigests = valueDigests.get(nameSpace);
    if (namespaceDigests != null) {
      return namespaceDigests.get(digestID);
    }
    return null;
  }

  /**
   * Retrieves the validation key required for token validation.
   *
   * @param chain the list of X509 certificates in the signature chain
   * @param parsedSignatureObject the parsed signature object to extract key information from
   * @param trustedKeys the list of trusted keys to validate against or null if all keys are trusted
   * @return the validation key if found or null if not found
   * @throws TokenValidationException if no validation key is found or there is a validation error
   */
  private PublicKey getValidationKey(
    List<X509Certificate> chain,
    Sign1COSEObject parsedSignatureObject,
    List<TrustedKey> trustedKeys
  ) throws TokenValidationException {
    boolean allTrusted = trustedKeys == null;
    PublicKey providedKey = chain.isEmpty()
      ? null
      : chain.getFirst().getPublicKey();
    String kid = getKeyId(parsedSignatureObject);
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
   * Retrieves the Key Identifier (kid) from the provided Sign1COSEObject,
   * preferring the key from protected attributes if present or else from unprotected attributes.
   *
   * <p>
   *   Note that the COSE standard states that KID can be stored in unprotected attributes but does not forbid
   *   storing it in protected attributes. The reason to look in protected attributes first, is because that information
   *   is signed and hence more trustworthy.
   * </p>
   *
   * @param parsedSignatureObject the Sign1COSEObject containing the signature attributes
   * @return the Key Identifier (kid) if found, or null if not found
   */
  private String getKeyId(Sign1COSEObject parsedSignatureObject) {
    CBORObject kidObject = Optional.ofNullable(
      parsedSignatureObject
        .getProtectedAttributes()
        .get(HeaderKeys.KID.AsCBOR())
    ).orElseGet(
      () ->
        parsedSignatureObject
          .getUnprotectedAttributes()
          .get(HeaderKeys.KID.AsCBOR())
    );
    return kidObject == null ? null : kidObject.AsString();
  }

  /**
   * Retrieves a list of X.509 certificates from a CBORObject representing an X.509 certificate chain.
   *
   * @param x5chain the CBORObject representing the X.509 certificate chain or null if no chain was provided
   * @return a list of X.509 certificates extracted from the CBORObject
   * @throws CertificateException if an error occurs during certificate processing
   */
  private List<X509Certificate> getChain(CBORObject x5chain)
    throws CertificateException, IOException {
    List<X509Certificate> chain = new ArrayList<>();
    if (x5chain == null) {
      return chain;
    }
    if (x5chain.getType().equals(CBORType.ByteString)) {
      chain.add(getCert(x5chain.GetByteString()));
    } else {
      for (int i = 0; i < x5chain.size(); i++) {
        CBORObject certObject = x5chain.get(i);
        chain.add(getCert(certObject.GetByteString()));
      }
    }
    return chain;
  }

  /**
   * Retrieves an X.509 certificate from the provided byte array.
   *
   * @param certBytes the byte array representing the X.509 certificate
   * @return the X.509 certificate extracted from the byte array
   * @throws CertificateException if an error occurs during certificate processing
   */
  private X509Certificate getCert(byte[] certBytes)
    throws CertificateException, IOException {
    try (InputStream is = new ByteArrayInputStream(certBytes)) {
      CertificateFactory certFactory = CertificateFactory.getInstance("X.509");
      return (X509Certificate) certFactory.generateCertificate(is);
    }
  }
}

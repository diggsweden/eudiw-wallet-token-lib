// SPDX-FileCopyrightText: 2024 Digg - Agency for Digital Government
//
// SPDX-License-Identifier: EUPL-1.2

package se.digg.wallet.datatypes.mdl.data;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;
import com.fasterxml.jackson.dataformat.cbor.CBORFactory;
import com.fasterxml.jackson.datatype.jsr310.JavaTimeModule;
import com.upokecenter.cbor.CBORObject;
import com.upokecenter.cbor.CBORType;
import com.upokecenter.numbers.EInteger;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.time.Instant;
import java.time.LocalDate;
import java.time.ZoneOffset;
import java.time.format.DateTimeFormatter;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;
import javax.crypto.KeyAgreement;
import lombok.extern.slf4j.Slf4j;
import org.bouncycastle.crypto.digests.SHA256Digest;
import org.bouncycastle.crypto.generators.HKDFBytesGenerator;
import org.bouncycastle.crypto.params.HKDFParameters;
import se.digg.cose.AlgorithmID;
import se.digg.cose.Attribute;
import se.digg.cose.COSEKey;
import se.digg.cose.CoseException;
import se.digg.cose.HeaderKeys;
import se.digg.cose.MAC0COSEObject;
import se.digg.cose.Sign1COSEObject;

/**
 * Utility class for handling CBOR (Concise Binary Object Representation) encoding,
 * decoding, and conversion functionalities. This class includes methods for
 * converting objects to CBOR format, parsing CBOR objects, and transforming CBOR
 * data into JSON or other formats. The utility also provides a signing mechanism
 * for CBOR data using a COSE-based signing process.
 */
@SuppressWarnings("PMD.CollapsibleIfStatements")
@Slf4j
public class CBORUtils {

  /**
   * Utility class for handling CBOR (Concise Binary Object Representation) operations.
   * This class is designed to provide helper methods for processing and managing CBOR data,
   * ensuring consistency and facilitating interactions with CBOR-encoded structures.
   *
   * This class is not intended to be instantiated. It provides only static utility methods for usage.
   */
  private CBORUtils() {}

  /** ObjectMapper for parsing serializing objects to CBOR */
  public static final ObjectMapper CBOR_MAPPER;
  /** Date formatter for dates */
  public static final DateTimeFormatter LOCAL_DATE_FORMATTER =
    DateTimeFormatter.ofPattern("yyyy-MM-dd");
  /** Time formatter for time */
  public static final DateTimeFormatter INSTANT_FORMATTER =
    DateTimeFormatter.ofPattern("yyyy-MM-dd'T'HH:mm:ss'Z'").withZone(
      ZoneOffset.UTC
    );

  static {
    CBOR_MAPPER = new ObjectMapper(new CBORFactory())
      .configure(SerializationFeature.WRITE_DATES_AS_TIMESTAMPS, false)
      .registerModule(new JavaTimeModule());
  }

  /**
   * Converts a value item expressed as Object to a CBORObject. This function only handles one
   * custom case (LocalDate).
   * If other custom data classes should be supported (such as driving_prileges), they need to be
   * assed here.
   *
   * @param o value
   * @return {@link CBORObject} representation of value
   */
  public static CBORObject convertValueToCBORObject(Object o) {
    if (o == null) {
      return null;
    }
    if (o instanceof LocalDate localDate) {
      String dateString = localDate.format(LOCAL_DATE_FORMATTER);
      return CBORObject.FromCBORObjectAndTag(
        CBORObject.FromString(dateString),
        EInteger.FromInt32(1004)
      );
    }
    if (o instanceof Instant instant) {
      String instantString = INSTANT_FORMATTER.format(instant);
      return CBORObject.FromCBORObjectAndTag(
        CBORObject.FromString(instantString),
        0
      );
    }
    return CBORObject.FromObject(o);
  }

  /**
   * Parses the given CBORObject and converts it into a corresponding Java object
   * based on its type or tag.
   *
   * @param cborElementValue the CBORObject to parse representing
   *                         a valid CBOR type or tagged value
   * @return the corresponding Java object derived from the CBORObject, which may
   *         include a string, byte array, boolean, list, map, or date, depending
   *         on the CBORObject's type or tag
   * @throws IllegalArgumentException if the CBORObject contains an unsupported
   *                                  tag or type
   */
  public static Object parseCBORObjectValue(CBORObject cborElementValue) {
    if (cborElementValue.isTagged()) {
      int tag = cborElementValue.getMostOuterTag().ToInt32Unchecked();
      if (tag == 1004) {
        String dateString = cborElementValue.AsString();
        return LocalDate.parse(dateString, LOCAL_DATE_FORMATTER);
      }
      throw new IllegalArgumentException("Unsupported CBOR tag: " + tag);
    } else {
      switch (cborElementValue.getType()) {
        case CBORType.TextString:
          return cborElementValue.AsString();
        case CBORType.ByteString:
          return cborElementValue.GetByteString();
        case CBORType.Boolean:
          return cborElementValue.AsBoolean();
        case CBORType.Array:
          return cborElementValue
            .getValues()
            .stream()
            .map(CBORUtils::parseCBORObjectValue)
            .collect(Collectors.toList());
        case CBORType.Map:
          Map<Object, Object> map = new HashMap<>();
          for (CBORObject key : cborElementValue.getKeys()) {
            map.put(
              parseCBORObjectValue(key),
              parseCBORObjectValue(cborElementValue.get(key))
            );
          }
          return map;
        default:
          throw new IllegalArgumentException(
            "Unsupported CBOR type: " + cborElementValue.getType()
          );
      }
    }
  }

  /**
   * Converts a CBOR-encoded byte array to its JSON string representation. The method decodes the CBOR byte array
   * into a CBOR object, untags it if it contains specific tagging, and then converts the resulting object to JSON.
   *
   * @param cborBytes the byte array containing CBOR-encoded data
   * @return the JSON string representation of the CBOR data
   */
  public static String cborToJson(byte[] cborBytes) {
    // Decode CBOR bytes to a CBOR object
    CBORObject cborObject = CBORObject.DecodeFromBytes(cborBytes);
    if (cborObject.isTagged()) {
      if (cborObject.getMostOuterTag().equals(EInteger.FromInt32(24))) {
        cborObject = cborObject.Untag();
        if (cborObject.getType().equals(CBORType.ByteString)) {
          cborObject = CBORObject.DecodeFromBytes(cborObject.GetByteString());
        }
      }
    }
    return cborObject.ToJSONString();
  }

  /**
   * Converts CBOR-encoded byte array into a human-readable, pretty-printed JSON string.
   *
   * @param cborBytes the input byte array containing CBOR-encoded data
   * @return the pretty-printed JSON string representation of the CBOR data
   * @throws IOException if there is an error during the conversion process
   */
  public static String cborToPrettyJson(byte[] cborBytes) throws IOException {
    // Decode CBOR bytes to a CBOR object
    String jsonString = cborToJson(cborBytes);
    ObjectMapper objectMapper = new ObjectMapper()
      .configure(SerializationFeature.WRITE_DATES_AS_TIMESTAMPS, false)
      .registerModule(new JavaTimeModule());

    return objectMapper
      .writerWithDefaultPrettyPrinter()
      .writeValueAsString(objectMapper.readValue(jsonString, Object.class));
  }

  /**
   * Signs the provided data using the specified key and algorithm, producing a Sign1 COSE signature.
   *
   * @param toBeSigned the byte array representing the content to be signed
   * @param key the COSEKey used for signing the content
   * @param algorithmID the algorithm identifier specifying the signing algorithm
   * @param kid the key identifier to be added to the COSE header, or null if not applicable
   * @param chain a list of X509Certificates representing the certificate chain to be added to the COSE header, or null if not applicable
   * @param protectedKid a flag indicating whether the key identifier should be placed in the protected header
   * @return a Sign1COSEObject representing the signed content with associated headers
   * @throws CoseException if an error occurs during the COSE signing process
   * @throws CertificateEncodingException if an encoding error occurs with the provided certificates
   */
  public static Sign1COSEObject sign(
    byte[] toBeSigned,
    COSEKey key,
    AlgorithmID algorithmID,
    String kid,
    List<X509Certificate> chain,
    boolean protectedKid
  ) throws CoseException, CertificateEncodingException {
    Sign1COSEObject coseSignature = new Sign1COSEObject(false);
    coseSignature.SetContent(toBeSigned);
    coseSignature.addAttribute(
      HeaderKeys.Algorithm,
      algorithmID.AsCBOR(),
      Attribute.PROTECTED
    );
    if (kid != null) {
      coseSignature.addAttribute(
        HeaderKeys.KID,
        CBORObject.FromString(kid),
        protectedKid ? Attribute.PROTECTED : Attribute.UNPROTECTED
      );
    }
    if (chain != null && !chain.isEmpty()) {
      CBORObject certChainObject;
      if (chain.size() == 1) {
        certChainObject = CBORObject.FromByteArray(chain.get(0).getEncoded());
      } else {
        certChainObject = CBORObject.NewArray();
        for (X509Certificate cert : chain) {
          certChainObject.Add(CBORObject.FromByteArray(cert.getEncoded()));
        }
      }
      coseSignature.addAttribute(
        HeaderKeys.x5chain,
        certChainObject,
        Attribute.UNPROTECTED
      );
    }
    coseSignature.sign(key);
    return coseSignature;
  }

  public static MAC0COSEObject deviceComputedMac(byte[] deviceAuthenticationBytes, PrivateKey privateKey, PublicKey publicKey) throws GeneralSecurityException, CoseException {
    byte[] sharedSecret = deriveSharedSecret(privateKey, publicKey);
    MAC0COSEObject mac0COSEObject = new MAC0COSEObject();
    mac0COSEObject.addAttribute(
      HeaderKeys.Algorithm,
      AlgorithmID.HMAC_SHA_256.AsCBOR(),
      Attribute.PROTECTED);
      mac0COSEObject.SetContent(deviceAuthenticationBytes);
    byte[] macKey = deriveEMacKey(sharedSecret, deviceAuthenticationBytes);
    mac0COSEObject.Create(macKey);
    return mac0COSEObject;
  }

  /**
   * Derives the EMacKey using the HKDF function as defined in RFC 5869.
   *
   * @param zab input keying material (IKM) as byte array.
   * @param sessionTranscriptBytes session transcript bytes to be hashed with SHA-256 as salt
   * @return A 32-byte EMacKey derived from HKDF.
   */
  public static byte[] deriveEMacKey(byte[] zab, byte[] sessionTranscriptBytes) {
    // Step 1: Create salt as SHA-256(sessionTranscriptBytes)
    SHA256Digest sha256Digest = new SHA256Digest(); // Use BouncyCastle's Digest
    byte[] salt = hash(sha256Digest, sessionTranscriptBytes);

    // Step 2: Define the info parameter as "EMacKey" encoded in UTF-8
    byte[] info = "EMacKey".getBytes(StandardCharsets.UTF_8);

    // Step 3: Setup HKDF parameters with SHA-256 hash, IKM, salt, and info.
    HKDFParameters hkdfParameters = new HKDFParameters(zab, salt, info);

    // Step 4: Create the HKDF generator
    HKDFBytesGenerator hkdfGenerator = new HKDFBytesGenerator(sha256Digest);

    // Step 5: Initialize the generator with our parameters
    hkdfGenerator.init(hkdfParameters);

    // Step 6: Generate the key (L = 32 bytes)
    byte[] eMacKey = new byte[32];
    hkdfGenerator.generateBytes(eMacKey, 0, eMacKey.length);

    // Return the derived EMacKey
    return eMacKey;
  }

  /**
   * Helper method to hash input data using a given Digest.
   *
   * @param digest The SHA-256 Digest instance.
   * @param input  The input data to hash.
   * @return The hashed result as a byte array.
   */
  private static byte[] hash(SHA256Digest digest, byte[] input) {
    digest.reset();
    digest.update(input, 0, input.length);
    byte[] output = new byte[digest.getDigestSize()];
    digest.doFinal(output, 0);
    return output;
  }



  /**
   * Derives a shared secret using Diffie-Hellman (DH) key derivation.
   *
   * @param privateKey The private key (either RSA or EC).
   * @param publicKey  The public key (must be of the same type as the private key).
   * @return A byte array representing the derived shared secret.
   * @throws IllegalArgumentException if the keys are not of the same type or unsupported key types are provided.
   * @throws GeneralSecurityException if key agreement fails.
   */
  public static byte[] deriveSharedSecret(PrivateKey privateKey, PublicKey publicKey)
    throws GeneralSecurityException {
    // Ensure the key types match
    if (privateKey instanceof RSAPrivateKey || publicKey instanceof RSAPublicKey) {
      throw new IllegalArgumentException("RSA keys cannot be used for key agreement (DH). Use EC keys instead.");
    } else if (privateKey instanceof ECPrivateKey && publicKey instanceof ECPublicKey) {
      return deriveECSharedSecret((ECPrivateKey) privateKey, (ECPublicKey) publicKey);
    } else {
      throw new IllegalArgumentException("Key types do not match or are unsupported. Use RSA or EC keys.");
    }
  }

  /**
   * Derives a shared secret using EC keys.
   *
   * @param privateKey The EC private key.
   * @param publicKey  The EC public key.
   * @return A byte array representing the derived shared secret.
   * @throws GeneralSecurityException if key agreement fails.
   */
  private static byte[] deriveECSharedSecret(ECPrivateKey privateKey, ECPublicKey publicKey)
    throws GeneralSecurityException {
    // Create EC Key Agreement
    KeyAgreement keyAgreement = KeyAgreement.getInstance("ECDH", "BC");
    keyAgreement.init(privateKey);
    keyAgreement.doPhase(publicKey, true);

    // Generate shared secret
    return keyAgreement.generateSecret();
  }

}

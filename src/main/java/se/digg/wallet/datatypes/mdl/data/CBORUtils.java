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
import java.security.PrivateKey;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.time.Instant;
import java.time.LocalDate;
import java.time.ZoneOffset;
import java.time.format.DateTimeFormatter;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

import lombok.extern.slf4j.Slf4j;
import se.digg.wallet.datatypes.common.TokenSigningAlgorithm;
import se.idsec.cose.*;

/**
 * Utility class for handling CBOR (Concise Binary Object Representation) encoding,
 * decoding, and conversion functionalities. This class includes methods for
 * converting objects to CBOR format, parsing CBOR objects, and transforming CBOR
 * data into JSON or other formats. The utility also provides a signing mechanism
 * for CBOR data using a COSE-based signing process.
 */
@Slf4j
public class CBORUtils {

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
   * @throws IOException if an error occurs during CBOR decoding
   */
  public static String cborToJson(byte[] cborBytes) throws IOException {
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

  public static Sign1COSEObject sign(byte[] toBeSigned, COSEKey key, AlgorithmID algorithmID, String kid, List<X509Certificate> chain, boolean protectedKid) throws IOException, CoseException, CertificateEncodingException {
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


}

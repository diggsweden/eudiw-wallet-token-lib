// SPDX-FileCopyrightText: 2024 Digg - Agency for Digital Government
//
// SPDX-License-Identifier: EUPL-1.2

package se.digg.wallet.datatypes.mdl.data;

import com.fasterxml.jackson.annotation.JsonIgnore;
import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.core.JsonGenerationException;
import com.fasterxml.jackson.core.JsonGenerator;
import com.fasterxml.jackson.databind.JsonSerializer;
import com.fasterxml.jackson.databind.SerializerProvider;
import com.fasterxml.jackson.databind.annotation.JsonSerialize;
import com.fasterxml.jackson.dataformat.cbor.CBORGenerator;
import com.upokecenter.cbor.CBORObject;
import java.io.IOException;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.time.Instant;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;
import se.digg.cose.AlgorithmID;
import se.digg.cose.COSEKey;
import se.digg.cose.CoseException;
import se.digg.cose.Sign1COSEObject;
import se.digg.wallet.datatypes.common.TokenParsingException;

/**
 * Represents the Mobile Security Object (MSO) used for secure verification and digital signatures
 * with associated metadata, key details, and validity information.
 * <p>
 * This class supports serialization and deserialization to/from CBOR format for cross-platform
 * compatibility and secure communication.
 * <p>
 * Features include:
 * - Representation of key and validity information related to the security of mobile devices.
 * - CBOR serialization and deserialization for the MSO and its nested objects.
 * - Signing functionality using cryptographic keys and algorithms.
 * <p>
 * An MSO consists of digest information, keys, metadata, and timestamps to ensure secure and
 * compliant operations.
 * <p>
 * The structure includes:
 * <ul>
 * <li>Version information.</li>
 * <li>Digest algorithm details.</li>
 * <li>Digest values mapped with associated metadata.</li>
 * <li>Device key data and authorizations.</li>
 * <li>Document type specification.</li>
 * <li>Validity timeframes for the MSO.</li>
 * </ul>
 *
 * Nested structures:
 * <ul>
 *   <li>{@code DeviceKeyInfo}: Contains key metadata, authorizations, and other key-related details.</li>
 *   <li>{@code ValidityInfo}: Represents validity timestamps like signed time, valid start, and expiration.</li>
 *   <li>{@code KeyAuthorizations}: Includes key authorizations pertaining to nameSpaces and data elements.</li>
 * </ul>
 *
 * The MSO can be signed using a digital key and validated for its authenticity.
 * <p>
 * API includes:
 * <ul>
 *   <li>Methods for signing the object using a key and certificate chain.</li>
 *   <li>Serialization to CBOR using customized logic.</li>
 *   <li>Deserialization of the CBOR-encoded MSO.</li>
 * </ul>
 *
 * Custom CBOR serialization is implemented via a nested {@code Serializer} class, ensuring accurate
 * representation of this object in the CBOR format.
 */
@Data
@AllArgsConstructor
@NoArgsConstructor
@Builder
@JsonInclude(JsonInclude.Include.NON_NULL)
@JsonSerialize(using = MobileSecurityObject.Serializer.class)
public class MobileSecurityObject {

  /** Version */
  private String version;
  /** Digest algorithm for digest values */
  private String digestAlgorithm;
  /** Digest values for attributes provided in the issuer signed structure */
  private Map<String, Map<Integer, byte[]>> valueDigests;
  /** wallet key */
  private DeviceKeyInfo deviceKeyInfo;
  /** type of mdoc document */
  private String docType;
  /** Validation information such as issue time and expiration time */
  private ValidityInfo validityInfo;

  /**
   * Builder class for creating instances of MobileSecurityObject.
   */
  public static class MobileSecurityObjectBuilder {} //lombok workaround

  // https://stackoverflow.com/questions/51947791/javadoc-cannot-find-symbol-error-when-using-lomboks-builder-annotation

  /**
   * Represents information related to a device key in the MobileSecurityObject.
   * This class includes the key itself, associated authorizations, and additional metadata.
   */
  @Data
  @AllArgsConstructor
  @NoArgsConstructor
  @Builder
  public static class DeviceKeyInfo {

    /** Wallet public key */
    private COSEKey deviceKey;
    /** Key authorizations */
    private KeyAuthorizations keyAuthorizations;
    /** Optional key info */
    private Map<Integer, Object> keyInfo;
  }

  /**
   * Represents the validity information of a digital security object.
   * This class contains the timestamps related to the signing, validity period,
   * and expected update of the associated security object.
   */
  @Data
  @AllArgsConstructor
  @NoArgsConstructor
  @Builder
  public static class ValidityInfo {

    /** Signing time */
    private Instant signed;
    /** Valid from time */
    private Instant validFrom;
    /** Expiration time */
    private Instant validUntil;
    /** Optional time for expected update */
    private Instant expectedUpdate;
  }

  /**
   * The KeyAuthorizations class represents key authorization details,
   * specifying access permissions for certain namespaces and data elements.
   */
  @Data
  @AllArgsConstructor
  @NoArgsConstructor
  @Builder
  public static class KeyAuthorizations {

    /** Name spaces this key is authorized for */
    private List<String> nameSpaces;
    /** Data element this key is authorized for */
    private List<String> dataElements;
  }

  /**
   * Signs the Mobile Security Object (MSO) using the specified certificate chain, key, and algorithm ID.
   *
   * @param chain the list of {@link X509Certificate} representing the certificate chain used for signing
   * @param key the {@link COSEKey} used to create the digital signature
   * @param algorithmID the {@link AlgorithmID} representing the algorithm used for signing
   * @return the signed object as a {@link CBORObject}
   * @throws IOException if an I/O error occurs during the signing process
   * @throws CoseException if an error related to the COSE signing process occurs
   * @throws CertificateEncodingException if an error occurs while encoding the certificates in the chain
   */
  @JsonIgnore
  public CBORObject sign(
    List<X509Certificate> chain,
    COSEKey key,
    AlgorithmID algorithmID
  ) throws IOException, CoseException, CertificateEncodingException {
    return sign(chain, key, algorithmID, null, false);
  }

  /**
   * Signs the Mobile Security Object (MSO) using the specified certificate chain, key, algorithm ID,
   * key identifier (KID), and KID protection flag.
   *
   * @param chain the list of {@link X509Certificate} representing the certificate chain used for signing
   * @param key the {@link COSEKey} used to create the digital signature
   * @param algorithmID the {@link AlgorithmID} representing the algorithm used for signing
   * @param kid a string that specifies the Key Identifier (KID) to include in the COSE structure
   * @param protectedKid a boolean flag indicating whether the KID is included as a protected attribute
   * @return the signed object as a {@link CBORObject}
   * @throws IOException if an I/O error occurs during the signing process
   * @throws CoseException if an error related to the COSE signing process occurs
   * @throws CertificateEncodingException if an error occurs while encoding the certificates in the chain
   */
  @JsonIgnore
  public CBORObject sign(
    List<X509Certificate> chain,
    COSEKey key,
    AlgorithmID algorithmID,
    String kid,
    boolean protectedKid
  ) throws IOException, CoseException, CertificateEncodingException {
    byte[] toBeSigned = CBORUtils.CBOR_MAPPER.writeValueAsBytes(this);
    Sign1COSEObject msg = CBORUtils.sign(
      toBeSigned,
      key,
      algorithmID,
      kid,
      chain,
      protectedKid
    );
    return msg.EncodeToCBORObject();
  }

  /**
   * The Serializer class is a custom implementation of the {@link JsonSerializer}
   * specifically for the {@link MobileSecurityObject} class. It is responsible for
   * serializing an instance of {@link MobileSecurityObject} into a CBOR encoded
   * representation using the {@link JsonGenerator}.
   * <p>
   * The serialization process involves encoding various fields of the
   * {@link MobileSecurityObject}, such as version, digest algorithm, value digests,
   * device key information, document type, and validity information, into their
   * respective CBOR representations.
   * <p>
   * This class ensures that the serialization adheres to the required format and
   * structure, and includes detailed handling of nested objects like
   * {@link MobileSecurityObject.DeviceKeyInfo} and
   * {@link MobileSecurityObject.KeyAuthorizations}. It also takes care of encoding
   * maps, lists, and byte arrays in a structured and deterministic manner using
   * CBOR utilities.
   */
  public static class Serializer extends JsonSerializer<MobileSecurityObject> {

    /** {@inheritDoc} */
    @Override
    public void serialize(
      MobileSecurityObject mso,
      JsonGenerator gen,
      SerializerProvider serializers
    ) throws IOException {
      try {
        CBORObject msoObject = CBORObject.NewOrderedMap();
        msoObject.set("version", CBORObject.FromString(mso.getVersion()));
        msoObject.set(
          "digestAlgorithm",
          CBORObject.FromString(mso.getDigestAlgorithm())
        );
        // Set Map<String, Map<Integer, byte[]>> valueDigests
        if (mso.getValueDigests() != null) {
          CBORObject valueDigestsObject = CBORObject.NewOrderedMap();
          for (Map.Entry<String, Map<Integer, byte[]>> entry : mso
            .getValueDigests()
            .entrySet()) {
            CBORObject innerMap = CBORObject.NewOrderedMap();
            if (entry.getValue() != null) {
              List<Integer> digestIdList = entry
                .getValue()
                .keySet()
                .stream()
                .sorted()
                .toList();
              for (Integer digestId : digestIdList) {
                innerMap.set(
                  digestId,
                  CBORObject.FromByteArray(entry.getValue().get(digestId))
                );
              }
            }
            valueDigestsObject.set(entry.getKey(), innerMap);
          }
          msoObject.set("valueDigests", valueDigestsObject);
          // Set DeviceKeyInfo
          if (mso.getDeviceKeyInfo() != null) {
            CBORObject deviceKeyInfoObject = CBORObject.NewOrderedMap();
            deviceKeyInfoObject.set(
              "deviceKey",
              new COSEKey(
                mso.getDeviceKeyInfo().getDeviceKey().AsPublicKey(),
                null
              ).AsCBOR()
            );
            KeyAuthorizations keyAuthorizations = mso
              .getDeviceKeyInfo()
              .getKeyAuthorizations();
            if (mso.getDeviceKeyInfo().getKeyInfo() != null) {
              deviceKeyInfoObject.set(
                "keyInfo",
                CBORObject.FromObject(mso.getDeviceKeyInfo().getKeyInfo())
              );
            }
            if (keyAuthorizations != null) {
              CBORObject keyAuthorizationsObject = CBORObject.NewOrderedMap();
              if (keyAuthorizations.getNameSpaces() != null) {
                keyAuthorizationsObject.set(
                  "nameSpaces",
                  CBORObject.FromCBORArray(
                    keyAuthorizations.nameSpaces
                      .stream()
                      .map(CBORObject::FromString)
                      .toArray(CBORObject[]::new)
                  )
                );
              }
              if (keyAuthorizations.getDataElements() != null) {
                keyAuthorizationsObject.set(
                  "dataElements",
                  CBORObject.FromCBORArray(
                    keyAuthorizations
                      .getDataElements()
                      .stream()
                      .map(CBORObject::FromString)
                      .toArray(CBORObject[]::new)
                  )
                );
              }
              deviceKeyInfoObject.set(
                "keyAuthorizations",
                keyAuthorizationsObject
              );
            }
            msoObject.set("deviceKeyInfo", deviceKeyInfoObject);
          }
          msoObject.set("docType", CBORObject.FromString(mso.getDocType()));

          if (mso.getValidityInfo() != null) {
            CBORObject validityInfoObject = CBORObject.NewOrderedMap();
            validityInfoObject.set(
              "signed",
              CBORUtils.convertValueToCBORObject(
                mso.getValidityInfo().getSigned()
              )
            );
            validityInfoObject.set(
              "validFrom",
              CBORUtils.convertValueToCBORObject(
                mso.getValidityInfo().getValidFrom()
              )
            );
            validityInfoObject.set(
              "validUntil",
              CBORUtils.convertValueToCBORObject(
                mso.getValidityInfo().getValidUntil()
              )
            );
            if (mso.getValidityInfo().getExpectedUpdate() != null) {
              validityInfoObject.set(
                "expectedUpdate",
                CBORUtils.convertValueToCBORObject(
                  mso.getValidityInfo().getExpectedUpdate()
                )
              );
            }
            msoObject.set("validityInfo", validityInfoObject);
          }
          byte[] value = msoObject.EncodeToBytes();

          if (gen instanceof CBORGenerator cborGen) {
            cborGen.writeTag(24);
            cborGen.writeBinary(value);
          } else {
            // Handle non-CBOR case, throw exception
            throw new JsonGenerationException("Non-CBOR generator used", gen);
          }
        }
      } catch (CoseException e) {
        throw new IOException(e);
      }
    }
  }

  /**
   * Deserializes the provided CBOR-encoded byte array into a MobileSecurityObject instance.
   *
   * @param cborBytes the CBOR-encoded byte array containing the data to be deserialized
   * @return the deserialized MobileSecurityObject
   * @throws TokenParsingException if an error occurs while parsing the CBOR byte array
   */
  public static MobileSecurityObject deserialize(byte[] cborBytes)
    throws TokenParsingException {
    // Initialize CBORObject from bytes
    try {
      CBORObject cbor = CBORObject.DecodeFromBytes(cborBytes);
      if (cbor.HasMostOuterTag(24)) {
        cbor = CBORObject.DecodeFromBytes(cbor.Untag().GetByteString());
      }

      // Extract values from CBORObject
      String version = cbor.get("version").AsString();
      String digestAlgorithm = cbor.get("digestAlgorithm").AsString();
      String docType = cbor.get("docType").AsString();

      // Populating valueDigests
      Map<String, Map<Integer, byte[]>> valueDigests = null;
      if (cbor.ContainsKey("valueDigests")) {
        valueDigests = new HashMap<>();
        CBORObject valueDigestsCbor = cbor.get("valueDigests");
        for (CBORObject key : valueDigestsCbor.getKeys()) {
          CBORObject innerMapCbor = valueDigestsCbor.get(key);
          Map<Integer, byte[]> innerMap = new HashMap<>();
          for (CBORObject digestId : innerMapCbor.getKeys()) {
            byte[] itemBytes = innerMapCbor.get(digestId).GetByteString();
            innerMap.put(digestId.AsInt32(), itemBytes);
          }
          valueDigests.put(key.AsString(), innerMap);
        }
      }

      DeviceKeyInfo deviceKeyInfo = null;
      if (cbor.ContainsKey("deviceKeyInfo")) {
        CBORObject deviceKeyInfoCbor = cbor.get("deviceKeyInfo");
        COSEKey deviceKey = new COSEKey(deviceKeyInfoCbor.get("deviceKey"));
        KeyAuthorizations keyAuthorizations = null;
        if (deviceKeyInfoCbor.ContainsKey("keyAuthorizations")) {
          CBORObject keyAuthorizationsCbor = deviceKeyInfoCbor.get(
            "keyAuthorizations"
          );
          List<String> dataElements = null;
          if (keyAuthorizationsCbor.ContainsKey("dataElements")) {
            CBORObject dataElementsCbor = keyAuthorizationsCbor.get(
              "dataElements"
            );
            dataElements = new ArrayList<>();
            for (CBORObject element : dataElementsCbor.getValues()) {
              dataElements.add(element.AsString());
            }
          }
          List<String> nameSpaces = null;
          if (keyAuthorizationsCbor.ContainsKey("nameSpaces")) {
            nameSpaces = new ArrayList<>();
            for (CBORObject element : keyAuthorizationsCbor
              .get("nameSpaces")
              .getValues()) {
              nameSpaces.add(element.AsString());
            }
          }
          keyAuthorizations = KeyAuthorizations.builder()
            .nameSpaces(nameSpaces)
            .dataElements(dataElements)
            .build();
        }
        Map<Integer, Object> keyInfo = null;
        if (deviceKeyInfoCbor.ContainsKey("keyInfo")) {
          keyInfo = new HashMap<>();
          CBORObject keyInfoCbor = deviceKeyInfoCbor.get("keyInfo");
          for (CBORObject key : keyInfoCbor.getKeys()) {
            keyInfo.put(
              key.AsInt32(),
              CBORUtils.CBOR_MAPPER.readValue(
                keyInfoCbor.get(key).EncodeToBytes(),
                Object.class
              )
            );
          }
        }
        deviceKeyInfo = DeviceKeyInfo.builder()
          .deviceKey(deviceKey)
          .keyAuthorizations(keyAuthorizations)
          .keyInfo(null)
          .build();
      }
      ValidityInfo validityInfo = null;
      if (cbor.ContainsKey("validityInfo")) {
        CBORObject validityInfoCbor = cbor.get("validityInfo");
        Instant signed = Instant.from(
          CBORUtils.INSTANT_FORMATTER.parse(
            validityInfoCbor.get("signed").AsString()
          )
        );
        Instant validFrom = Instant.from(
          CBORUtils.INSTANT_FORMATTER.parse(
            validityInfoCbor.get("validFrom").AsString()
          )
        );
        Instant validUntil = Instant.from(
          CBORUtils.INSTANT_FORMATTER.parse(
            validityInfoCbor.get("validUntil").AsString()
          )
        );
        Instant expectedUpdate = null;
        if (validityInfoCbor.ContainsKey("expectedUpdate")) {
          expectedUpdate = Instant.from(
            CBORUtils.INSTANT_FORMATTER.parse(
              validityInfoCbor.get("expectedUpdate").AsString()
            )
          );
        }
        validityInfo = ValidityInfo.builder()
          .signed(signed)
          .validFrom(validFrom)
          .validUntil(validUntil)
          .expectedUpdate(expectedUpdate)
          .build();
      }

      // Construct and return MobileSecurityObject
      MobileSecurityObject mobileSecurityObject = new MobileSecurityObject();
      mobileSecurityObject.setVersion(version);
      mobileSecurityObject.setDigestAlgorithm(digestAlgorithm);
      mobileSecurityObject.setValueDigests(valueDigests);
      mobileSecurityObject.setDeviceKeyInfo(deviceKeyInfo);
      mobileSecurityObject.setDocType(docType);
      mobileSecurityObject.setValidityInfo(validityInfo);

      return mobileSecurityObject;
    } catch (Exception e) {
      throw new TokenParsingException(
        "Error parsing MobileSecurityObject from CBOR",
        e
      );
    }
  }
}

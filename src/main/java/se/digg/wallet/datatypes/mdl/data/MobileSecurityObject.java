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
import se.digg.wallet.datatypes.common.TokenParsingException;
import se.idsec.cose.*;

@Data
@AllArgsConstructor
@NoArgsConstructor
@Builder
@JsonInclude(JsonInclude.Include.NON_NULL)
@JsonSerialize(using = MobileSecurityObject.Serializer.class)
public class MobileSecurityObject {

  private String version;
  private String digestAlgorithm;
  private Map<String, Map<Integer, byte[]>> valueDigests;
  private DeviceKeyInfo deviceKeyInfo;
  private String docType;
  private ValidityInfo validityInfo;

  public static class MobileSecurityObjectBuilder {} //lombok workaround

  // https://stackoverflow.com/questions/51947791/javadoc-cannot-find-symbol-error-when-using-lomboks-builder-annotation
  @Data
  @AllArgsConstructor
  @NoArgsConstructor
  @Builder
  public static class DeviceKeyInfo {

    private COSEKey deviceKey;
    private KeyAuthorizations keyAuthorizations;
    private Map<Integer, Object> keyInfo;
  }

  @Data
  @AllArgsConstructor
  @NoArgsConstructor
  @Builder
  public static class ValidityInfo {

    private Instant signed;
    private Instant validFrom;
    private Instant validUntil;
    private Instant expectedUpdate;
  }

  @Data
  @AllArgsConstructor
  @NoArgsConstructor
  @Builder
  public static class KeyAuthorizations {

    private List<String> nameSpaces;
    private List<String> dataElements;
  }

  @JsonIgnore
  public CBORObject sign(
    List<X509Certificate> chain,
    COSEKey key,
    AlgorithmID algorithmID
  )
    throws IOException, CoseException, CertificateEncodingException {
    return sign(chain, key, algorithmID, null, false);
  }

  @JsonIgnore
  public CBORObject sign(
    List<X509Certificate> chain,
    COSEKey key,
    AlgorithmID algorithmID,
    String kid,
    boolean protectedKid
  )
    throws IOException, CoseException, CertificateEncodingException {
    byte[] toBeSigned = CBORUtils.CBOR_MAPPER.writeValueAsBytes(this);
    Sign1COSEObject msg = CBORUtils.sign(toBeSigned, key, algorithmID, kid, chain, protectedKid);
    return msg.EncodeToCBORObject();
  }

  public static class Serializer extends JsonSerializer<MobileSecurityObject> {

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
      throw new TokenParsingException("Error parsing MobileSecurityObject from CBOR", e);
    }
  }
}

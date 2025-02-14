// SPDX-FileCopyrightText: 2025 Digg - Agency for Digital Government
//
// SPDX-License-Identifier: EUPL-1.2

package se.digg.wallet.datatypes.mdl.data;

import com.fasterxml.jackson.core.JsonGenerationException;
import com.fasterxml.jackson.core.JsonGenerator;
import com.fasterxml.jackson.databind.JsonSerializer;
import com.fasterxml.jackson.databind.SerializerProvider;
import com.fasterxml.jackson.databind.annotation.JsonSerialize;
import com.fasterxml.jackson.dataformat.cbor.CBORGenerator;
import com.upokecenter.cbor.CBORObject;
import com.upokecenter.numbers.EInteger;
import java.io.IOException;
import lombok.AllArgsConstructor;
import lombok.Data;
import se.digg.wallet.datatypes.common.TokenParsingException;

/**
 * The DeviceResponse class represents a mDL presentation token as it is returned as response to a presentation request
 * with information such as document type, status, version, and associated cryptographic data.
 * It provides functionality for serialization and deserialization using CBOR (Concise Binary Object Representation).
 * The object can be converted into and parsed from a CBOR-encoded byte array for data transmission.
 * <p>
 * This class includes the following key components:
 * - Metadata about the response, such as document type, version, and status.
 * - Cryptographic elements, including issuer-signed data, device signature, and optional device MAC key.
 * - A serializer implementation for converting the object to CBOR format.
 */
@Data
@AllArgsConstructor
@JsonSerialize(using = DeviceResponse.Serializer.class)
public class DeviceResponse {

  /**
   * Constructor for the DeviceResponse class.
   * Initializes a new instance of the DeviceResponse with the specified parameters.
   * including signature device authentication
   *
   * @param docType the document type associated with the response.
   * @param issuerSigned the issuer-signed data associated with the device response.
   * @param deviceSignature the byte array representing the device signature.
   */
  public DeviceResponse(
    String docType,
    IssuerSigned issuerSigned,
    byte[] deviceSignature
  ) {
    this.issuerSigned = issuerSigned;
    this.deviceSignature = deviceSignature;
    this.docType = docType;
    this.version = "1.0";
    this.status = 0;
    this.deviceNameSpaces = CBORObject.NewMap();
    this.deviceMac = null;
  }

  /**
   * Constructor for the DeviceResponse class.
   * Initializes a new instance of the DeviceResponse with the specified parameters
   * including MAC device authentication.
   *
   * @param deviceMac the byte array representing the device MAC.
   * @param docType the document type associated with the response.
   * @param issuerSigned the issuer-signed data associated with the device response.
   */
  public DeviceResponse(
    byte[] deviceMac,
    String docType,
    IssuerSigned issuerSigned
  ) {
    this.issuerSigned = issuerSigned;
    this.docType = docType;
    this.version = "1.0";
    this.status = 0;
    this.deviceNameSpaces = CBORObject.NewMap();
    this.deviceMac = deviceMac;
    this.deviceSignature = null;
  }

  /** Status code. Default 0 for successful responses */
  private final int status;
  /** DocType for the response document */
  private final String docType;
  /** Version. Shall be 1.0 */
  private final String version;
  /** The IssuerSigned object */
  private final IssuerSigned issuerSigned;
  /** The object providing the name spaces data for the device signature. By default, this is an empty map. */
  private final CBORObject deviceNameSpaces;
  /** The bytes of the device signature */
  private final byte[] deviceSignature;
  /** The bytes of a wallet provided MAC */
  private final byte[] deviceMac;

  /**
   * A custom serializer for the {@code DeviceResponse} class that converts a {@code DeviceResponse}
   * object into its CBOR representation. This class extends the {@code JsonSerializer} to provide
   * specific serialization logic for {@code DeviceResponse} objects.
   * <p>
   * The serialization process involves the creation and encoding of a CBOR object that encapsulates
   * key fields from the {@code DeviceResponse} instance, including device signature, device MAC,
   * namespaces, document type, issuer-signed data, and version details.
   * <p>
   * The serializer explicitly supports CBOR output, leveraging a {@code CBORGenerator} to output
   * the serialized bytes. If a non-CBOR generator is provided, an exception is thrown.
   * <p>
   * Exception Handling:
   * <ul>
   * <li>Throws {@link IOException} for errors during the serialization process or CBOR encoding.</li>
   * <li>Throws {@link JsonGenerationException} if a non-CBOR generator is used.</li>
   * </ul>
   */
  public static class Serializer extends JsonSerializer<DeviceResponse> {

    /** {@inheritDoc} **/
    @Override
    public void serialize(
      DeviceResponse deviceResponse,
      JsonGenerator gen,
      SerializerProvider serializers
    ) throws IOException {
      CBORObject deviceSignatureMap = CBORObject.NewMap();
      if (deviceResponse.getDeviceSignature() != null) {
        deviceSignatureMap.Add(
          CBORObject.FromString("deviceSignature"),
          CBORObject.DecodeFromBytes(deviceResponse.getDeviceSignature())
        );
      }
      if (deviceResponse.getDeviceMac() != null) {
        deviceSignatureMap.Add(
          CBORObject.FromString("deviceMac"),
          CBORObject.DecodeFromBytes(deviceResponse.getDeviceMac())
        );
      }

      CBORObject deviceSigned = CBORObject.NewOrderedMap();
      deviceSigned.Add(
        CBORObject.FromString("nameSpaces"),
        CBORObject.FromCBORObjectAndTag(
          CBORObject.FromByteArray(
            deviceResponse.getDeviceNameSpaces().EncodeToBytes()
          ),
          EInteger.FromInt32(24)
        )
      );
      deviceSigned.Add(CBORObject.FromString("deviceAuth"), deviceSignatureMap);

      CBORObject docArray = CBORObject.NewArray();
      CBORObject mdoc = CBORObject.NewOrderedMap();
      mdoc.Add(
        CBORObject.FromString("docType"),
        CBORObject.FromString(deviceResponse.getDocType())
      );
      mdoc.Add(
        CBORObject.FromString("issuerSigned"),
        CBORObject.DecodeFromBytes(
          CBORUtils.CBOR_MAPPER.writeValueAsBytes(
            deviceResponse.getIssuerSigned()
          )
        )
      );
      mdoc.Add(CBORObject.FromString("deviceSigned"), deviceSigned);
      docArray.Add(mdoc);

      CBORObject deviceResponseCbor = CBORObject.NewOrderedMap();
      deviceResponseCbor.Add(
        CBORObject.FromString("version"),
        CBORObject.FromString(deviceResponse.getVersion())
      );
      deviceResponseCbor.Add(CBORObject.FromString("documents"), docArray);
      deviceResponseCbor.Add(
        CBORObject.FromString("status"),
        CBORObject.FromInt32(0)
      );

      // Generate serialized CBOR bytes
      byte[] value = deviceResponseCbor.EncodeToBytes();

      if (gen instanceof CBORGenerator cborGen) {
        cborGen.writeBytes(value, 0, value.length);
      } else {
        // Handle non-CBOR case, throw exception
        throw new JsonGenerationException("Non-CBOR generator used", gen);
      }
    }
  }

  /**
   * Deserializes a CBOR-encoded byte array into a DeviceResponse object.
   *
   * @param cborEncoded the byte array containing the CBOR-encoded data to be deserialized.
   * @return a DeviceResponse object with the deserialized data.
   * @throws TokenParsingException if an error occurs during the deserialization process.
   */
  public static DeviceResponse deserialize(byte[] cborEncoded)
    throws TokenParsingException {
    try {
      CBORObject deviceResponseObject = CBORObject.DecodeFromBytes(cborEncoded);
      String version = deviceResponseObject.get("version").AsString();
      int status = deviceResponseObject.get("status").AsInt32();
      CBORObject documents = deviceResponseObject.get("documents");
      CBORObject doc = documents.get(0);
      IssuerSigned issuerSigned = IssuerSigned.deserialize(
        doc.get("issuerSigned").EncodeToBytes()
      );
      String docType = doc.get("docType").AsString();
      CBORObject deviceSigned = doc.get("deviceSigned");
      CBORObject deviceNameSpaces = CBORObject.DecodeFromBytes(
        deviceSigned.get("nameSpaces").Untag().GetByteString()
      );
      CBORObject deviceAuth = deviceSigned.get("deviceAuth");
      byte[] deviceSignature = deviceAuth.get("deviceSignature") != null
        ? deviceAuth.get("deviceSignature").EncodeToBytes()
        : null;
      byte[] deviceMac = deviceAuth.get("deviceMac") != null
        ? deviceAuth.get("deviceMac").EncodeToBytes()
        : null;

      return new DeviceResponse(
        status,
        docType,
        version,
        issuerSigned,
        deviceNameSpaces,
        deviceSignature,
        deviceMac
      );
    } catch (Exception e) {
      throw new TokenParsingException("Failed to parse Device Response", e);
    }
  }
}

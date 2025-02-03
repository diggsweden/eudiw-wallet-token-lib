package se.digg.wallet.datatypes.mdl.data;

import com.fasterxml.jackson.core.JsonGenerationException;
import com.fasterxml.jackson.core.JsonGenerator;
import com.fasterxml.jackson.databind.JsonSerializer;
import com.fasterxml.jackson.databind.SerializerProvider;
import com.fasterxml.jackson.databind.annotation.JsonSerialize;
import com.fasterxml.jackson.dataformat.cbor.CBORGenerator;
import com.upokecenter.cbor.CBORObject;
import com.upokecenter.numbers.EInteger;
import lombok.AllArgsConstructor;
import lombok.Data;

import java.io.IOException;

@Data
@AllArgsConstructor
@JsonSerialize(using = DeviceResponse.Serializer.class)
public class DeviceResponse {

  public DeviceResponse(String docType, IssuerSigned issuerSigned, byte[] deviceSignature) {
    this.issuerSigned = issuerSigned;
    this.deviceSignature = deviceSignature;
    this.docType = docType;
    this.version = "1.0";
    this.status = 0;
    this.deviceNameSpaces = CBORObject.NewMap();
    this.deviceMac = null;
  }

  int status;
  String docType;
  String version;
  IssuerSigned issuerSigned;
  CBORObject deviceNameSpaces;
  byte[] deviceSignature;
  byte[] deviceMac;

  public static class Serializer extends JsonSerializer<DeviceResponse> {

    @Override
    public void serialize(
      DeviceResponse deviceResponse,
      JsonGenerator gen,
      SerializerProvider serializers
    ) throws IOException {

      CBORObject deviceSignatureMap = CBORObject.NewMap();
      if (deviceResponse.getDeviceSignature() != null) {
        deviceSignatureMap.Add(CBORObject.FromString("deviceSignature"),
          CBORObject.DecodeFromBytes(deviceResponse.getDeviceSignature()));
      }
      if (deviceResponse.getDeviceMac() != null) {
        deviceSignatureMap.Add(CBORObject.FromString("deviceMac"),
          CBORObject.DecodeFromBytes(deviceResponse.getDeviceMac()));
      }

      CBORObject deviceSigned = CBORObject.NewOrderedMap();
      deviceSigned.Add(CBORObject.FromString("nameSpaces"),
        CBORObject.FromCBORObjectAndTag(CBORObject.FromByteArray(deviceResponse.getDeviceNameSpaces().EncodeToBytes()),
          EInteger.FromInt32(24)));
      deviceSigned.Add(CBORObject.FromString("deviceAuth"), deviceSignatureMap);

      CBORObject docArray = CBORObject.NewArray();
      CBORObject mdoc = CBORObject.NewOrderedMap();
      mdoc.Add(CBORObject.FromString("docType"), CBORObject.FromString(deviceResponse.getDocType()));
      mdoc.Add(CBORObject.FromString("issuerSigned"),
        CBORObject.DecodeFromBytes(CBORUtils.CBOR_MAPPER.writeValueAsBytes(deviceResponse.getIssuerSigned())));
      mdoc.Add(CBORObject.FromString("deviceSigned"), deviceSigned);
      docArray.Add(mdoc);

      CBORObject deviceResponseCbor = CBORObject.NewOrderedMap();
      deviceResponseCbor.Add(CBORObject.FromString("version"), CBORObject.FromString(deviceResponse.getVersion()));
      deviceResponseCbor.Add(CBORObject.FromString("documents"), docArray);
      deviceResponseCbor.Add(CBORObject.FromString("status"), CBORObject.FromInt32(0));

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
}


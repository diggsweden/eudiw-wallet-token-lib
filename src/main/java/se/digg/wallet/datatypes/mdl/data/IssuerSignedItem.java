package se.digg.wallet.datatypes.mdl.data;

import com.fasterxml.jackson.annotation.JsonIgnore;
import com.fasterxml.jackson.core.*;
import com.fasterxml.jackson.databind.DeserializationContext;
import com.fasterxml.jackson.databind.JsonDeserializer;
import com.fasterxml.jackson.databind.JsonSerializer;
import com.fasterxml.jackson.databind.SerializerProvider;
import com.fasterxml.jackson.databind.annotation.JsonDeserialize;
import com.fasterxml.jackson.databind.annotation.JsonSerialize;
import com.fasterxml.jackson.dataformat.cbor.CBORGenerator;
import com.fasterxml.jackson.dataformat.cbor.CBORParser;
import com.upokecenter.cbor.CBORObject;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;
import lombok.extern.slf4j.Slf4j;

import java.io.IOException;

/**
 * Description
 */
@Data
@AllArgsConstructor
@NoArgsConstructor
@Builder
@Slf4j
@JsonSerialize(using = IssuerSignedItem.Serializer.class)
@JsonDeserialize(using = IssuerSignedItem.Deserializer.class)
public class IssuerSignedItem {
  int digestID;
  byte[] random;
  String elementIdentifier;
  Object elementValue;

  @JsonIgnore
  public byte[] toBeHashedBytes() throws JsonProcessingException {
    return CBORUtils.CBOR_MAPPER.writeValueAsBytes(this);
  }

  public static class Serializer extends JsonSerializer<IssuerSignedItem> {
    @Override
    public void serialize(IssuerSignedItem issuerSignedItem, JsonGenerator gen, SerializerProvider serializers) throws IOException {

      CBORObject map = CBORObject.NewOrderedMap();
      map.set("digestID", CBORObject.FromInt32(issuerSignedItem.digestID));
      map.set("random", CBORObject.FromByteArray(issuerSignedItem.random));
      map.set("elementIdentifier", CBORObject.FromString(issuerSignedItem.elementIdentifier));
      map.set("elementValue", CBORUtils.convertValueToCBORObject(issuerSignedItem.elementValue));

      // Generate serialized CBOR bytes
      byte[] value = map.EncodeToBytes();

      if (gen instanceof CBORGenerator cborGen) {
        cborGen.writeTag(24);
        cborGen.writeBinary(value);
      } else {
        // Handle non-CBOR case, throw exception
        throw new JsonGenerationException("Non-CBOR generator used", gen);
      }
    }
  }

  public static class Deserializer extends JsonDeserializer<IssuerSignedItem> {

    @Override
    public IssuerSignedItem deserialize(JsonParser gen, DeserializationContext ctxt)
      throws IOException, JsonProcessingException {

      if (gen instanceof CBORParser) {
        byte[] value = gen.getBinaryValue();
        // Parse CBOR
        CBORObject cbor = CBORObject.DecodeFromBytes(value);

        // Extract values from the CBOR Object
        int digestID = cbor.get("digestID").AsInt32();
        byte[] random = cbor.get("random").GetByteString();
        String elementIdentifier = cbor.get("elementIdentifier").AsString();
        Object elementValue = CBORUtils.parseCBORObjectValue(cbor.get("elementValue"));

        // Construct and return result
        return new IssuerSignedItem(digestID, random, elementIdentifier, elementValue);
      } else {
        // Handle non-CBOR case, throw exception
        throw new JsonParseException(gen, "Non-CBOR parser used");
      }
    }
  }

}

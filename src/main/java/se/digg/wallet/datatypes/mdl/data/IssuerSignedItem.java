// SPDX-FileCopyrightText: 2024 Digg - Agency for Digital Government
//
// SPDX-License-Identifier: EUPL-1.2

package se.digg.wallet.datatypes.mdl.data;

import com.fasterxml.jackson.annotation.JsonIgnore;
import com.fasterxml.jackson.core.JsonGenerationException;
import com.fasterxml.jackson.core.JsonGenerator;
import com.fasterxml.jackson.core.JsonParseException;
import com.fasterxml.jackson.core.JsonParser;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.DeserializationContext;
import com.fasterxml.jackson.databind.JsonDeserializer;
import com.fasterxml.jackson.databind.JsonSerializer;
import com.fasterxml.jackson.databind.SerializerProvider;
import com.fasterxml.jackson.databind.annotation.JsonDeserialize;
import com.fasterxml.jackson.databind.annotation.JsonSerialize;
import com.fasterxml.jackson.dataformat.cbor.CBORGenerator;
import com.fasterxml.jackson.dataformat.cbor.CBORParser;
import com.upokecenter.cbor.CBORObject;
import java.io.IOException;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;
import lombok.extern.slf4j.Slf4j;

/**
 * Represents an issuer-signed item containing an instance of disclosed attribute data associated with an mDL document.
 * This class is serialized and deserialized using CBOR (Concise Binary Object Representation),
 * adhering to specific encoding and decoding mechanisms provided via custom serializers
 * and deserializers.
 * <p>
 * Fields:
 * <ul>
 * <li>`digestID`: An integer identifier for the digest provided in the Mobile Security Object (MSO)</li>
 * <li>`random`: A random salt mixed with attribute data during hashing</li>
 * <li>`elementIdentifier`: A name uniquely identifying the attribute</li>
 * <li>`elementValue`: The disclosed attribute value</li>
 * </ul>
 *
 * Nested Classes:
 * <ul>
 * <li>`Serializer`: Custom serializer for transforming an IssuerSignedItem instance
 * into the CBOR binary format, implementing {@link JsonSerializer}.</li>
 * <li>`Deserializer`: Custom deserializer for reconstructing an IssuerSignedItem instance
 * from the CBOR binary format, implementing {@link JsonDeserializer}.</li>
 * </ul>
 */
@Data
@AllArgsConstructor
@NoArgsConstructor
@Builder
@Slf4j
@JsonSerialize(using = IssuerSignedItem.Serializer.class)
@JsonDeserialize(using = IssuerSignedItem.Deserializer.class)
public class IssuerSignedItem {

  /** An integer identifier for the digest provided in the Mobile Security Object (MSO) */
  int digestID;
  /** A random salt mixed with attribute data during hashing */
  byte[] random;
  /** A name uniquely identifying the attribute */
  String elementIdentifier;
  /** The disclosed attribute value */
  Object elementValue;

  /**
   * Converts the current object into its CBOR (Concise Binary Object Representation) byte array representation.
   * This includes wrapping the object inside a CBOR tag 24 (CBOR encoded data)
   *
   * @return a byte array containing the CBOR-encoded representation of the object.
   * @throws JsonProcessingException if an error occurs during the processing of the object to CBOR format.
   */
  @JsonIgnore
  public byte[] toBeHashedBytes() throws JsonProcessingException {
    return CBORUtils.CBOR_MAPPER.writeValueAsBytes(this);
  }

  /**
   * Serializer class for serializing IssuerSignedItem objects into a CBOR representation.
   * Extends the {@code JsonSerializer<IssuerSignedItem>} class to provide custom serialization logic.
   */
  public static class Serializer extends JsonSerializer<IssuerSignedItem> {

    @Override
    public void serialize(
      IssuerSignedItem issuerSignedItem,
      JsonGenerator gen,
      SerializerProvider serializers
    ) throws IOException {
      CBORObject map = CBORObject.NewOrderedMap();
      map.set("digestID", CBORObject.FromInt32(issuerSignedItem.digestID));
      map.set("random", CBORObject.FromByteArray(issuerSignedItem.random));
      map.set(
        "elementIdentifier",
        CBORObject.FromString(issuerSignedItem.elementIdentifier)
      );
      map.set(
        "elementValue",
        CBORUtils.convertValueToCBORObject(issuerSignedItem.elementValue)
      );

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

  /**
   * Deserializer class is responsible for deserializing JSON data into an
   * IssuerSignedItem object, specifically handling data in CBOR (Concise Binary
   * Object Representation) format.
   * <p>
   * This class extends the JsonDeserializer class provided by Jackson, and it
   * overrides the {@code deserialize} method to provide custom deserialization logic.
   * If the input data is not in CBOR format, an exception is thrown.
   * <p>
   * The deserialization process involves:
   * - Parsing the input binary value into a CBORObject.
   * - Extracting individual fields such as digestID, random, elementIdentifier,
   *   and elementValue from the CBORObject.
   * - Constructing an IssuerSignedItem object using the extracted values.
   * <p>
   * Throws:
   * - JsonParseException if the input parser is not a CBORParser.
   * - IOException in case of I/O errors during deserialization.
   */
  public static class Deserializer extends JsonDeserializer<IssuerSignedItem> {

    /** {@inheritDoc} */
    @Override
    public IssuerSignedItem deserialize(
      JsonParser gen,
      DeserializationContext ctxt
    ) throws IOException {
      if (gen instanceof CBORParser) {
        byte[] value = gen.getBinaryValue();
        // Parse CBOR
        CBORObject cbor = CBORObject.DecodeFromBytes(value);

        // Extract values from the CBOR Object
        int digestID = cbor.get("digestID").AsInt32();
        byte[] random = cbor.get("random").GetByteString();
        String elementIdentifier = cbor.get("elementIdentifier").AsString();
        Object elementValue = CBORUtils.parseCBORObjectValue(
          cbor.get("elementValue")
        );

        // Construct and return result
        return new IssuerSignedItem(
          digestID,
          random,
          elementIdentifier,
          elementValue
        );
      } else {
        // Handle non-CBOR case, throw exception
        throw new JsonParseException(gen, "Non-CBOR parser used");
      }
    }
  }
}

package se.digg.wallet.datatypes.mdl.data;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;
import com.fasterxml.jackson.dataformat.cbor.CBORFactory;
import com.fasterxml.jackson.datatype.jsr310.JavaTimeModule;
import com.upokecenter.cbor.CBORObject;
import com.upokecenter.cbor.CBORType;
import com.upokecenter.numbers.EInteger;
import lombok.extern.slf4j.Slf4j;

import java.io.IOException;
import java.time.Instant;
import java.time.LocalDate;
import java.time.ZoneOffset;
import java.time.format.DateTimeFormatter;
import java.util.HashMap;
import java.util.Map;
import java.util.stream.Collectors;

/**
 * Description
 */
@Slf4j
public class CBORUtils {

  public static final ObjectMapper CBOR_MAPPER;
  public static final DateTimeFormatter LOCAL_DATE_FORMATTER = DateTimeFormatter.ofPattern("yyyy-MM-dd");
  public static final DateTimeFormatter INSTANT_FORMATTER = DateTimeFormatter.ofPattern("yyyy-MM-dd'T'HH:mm:ss'Z'")
    .withZone(ZoneOffset.UTC);



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
      return CBORObject.FromCBORObjectAndTag(CBORObject.FromString(dateString), EInteger.FromInt32(1004));
    }
    if (o instanceof Instant instant) {
      String instantString = INSTANT_FORMATTER.format(instant);
      return CBORObject.FromCBORObjectAndTag(CBORObject.FromString(instantString), 0);
    }
    return CBORObject.FromObject(o);
  }

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
        return cborElementValue.getValues().stream()
          .map(CBORUtils::parseCBORObjectValue)
          .collect(Collectors.toList());
      case CBORType.Map:
        Map<Object, Object> map = new HashMap<>();
        for (CBORObject key : cborElementValue.getKeys()) {
          map.put(parseCBORObjectValue(key), parseCBORObjectValue(cborElementValue.get(key)));
        }
        return map;
      default:
        throw new IllegalArgumentException("Unsupported CBOR type: " + cborElementValue.getType());
      }
    }
  }

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
  public static String cborToPrettyJson(byte[] cborBytes) throws IOException {
    // Decode CBOR bytes to a CBOR object
    String jsonString = cborToJson(cborBytes);
    ObjectMapper objectMapper = new ObjectMapper()
      .configure(SerializationFeature.WRITE_DATES_AS_TIMESTAMPS, false)
      .registerModule(new JavaTimeModule());

    return objectMapper.writerWithDefaultPrettyPrinter().writeValueAsString(
      objectMapper.readValue(jsonString, Object.class)
    );
  }
}


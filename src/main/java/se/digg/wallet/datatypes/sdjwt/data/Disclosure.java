// SPDX-FileCopyrightText: 2024 Digg - Agency for Digital Government
//
// SPDX-License-Identifier: EUPL-1.2

package se.digg.wallet.datatypes.sdjwt.data;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.core.type.TypeReference;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.List;
import java.util.Random;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;
import org.bouncycastle.crypto.CryptoServicesRegistrar;
import se.digg.wallet.datatypes.common.TokenAttribute;
import se.digg.wallet.datatypes.common.TokenValidationException;
import se.digg.wallet.datatypes.sdjwt.JSONUtils;

/**
 * SD JWT disclosure data
 */
@Data
@AllArgsConstructor
@NoArgsConstructor
public class Disclosure {

  /** Random source */
  public static final Random RNG = CryptoServicesRegistrar.getSecureRandom();

  /** The random salt value of the disclosure */
  private String salt;
  /** The name of the disclosed attribute when applicable */
  private String name;
  /** The disclosed attribute value */
  private Object value;
  /** The base64 disclosure string being attached to an SD JWT structure representing this disclosure */
  private String disclosure;

  /**
   * Constructs a new Disclosure instance using the provided TokenAttribute.
   * This constructor generates a random salt, extracts relevant information
   * from the TokenAttribute, and creates a base64-encoded disclosure string.
   *
   * @param tokenAttribute the TokenAttribute object containing the type (name)
   *                       and value of the attribute to be disclosed. If the
   *                       type is not null, its name will be included in the
   *                       disclosure along with the value; otherwise, only the
   *                       value will be included
   * @throws JsonProcessingException if there is an error during the JSON
   *                                 serialization process while creating the
   *                                 disclosure string
   */
  public Disclosure(TokenAttribute tokenAttribute)
    throws JsonProcessingException {
    this.salt = Base64.getUrlEncoder()
      .withoutPadding()
      .encodeToString(new BigInteger(128, RNG).toByteArray());
    this.name = tokenAttribute.getType() != null
      ? tokenAttribute.getType().getAttributeName()
      : null;
    this.value = tokenAttribute.getValue();
    this.disclosure = name != null
      ? JSONUtils.JSON_MAPPER.writeValueAsString(
        List.of(this.salt, this.name, this.value)
      )
      : JSONUtils.JSON_MAPPER.writeValueAsString(
        List.of(this.salt, this.value)
      );
  }

  /**
   * Constructs a new Disclosure instance using the provided base64 URL-encoded disclosure string.
   * This constructor decodes the string, parses it into components, and initializes
   * the salt, name, and value fields based on the content of the parsed disclosure string.
   *
   * @param disclosureB64Url the base64 URL-encoded string representing the disclosure. This string
   *                         must contain the salt as the first value and can optionally include
   *                         the name of the attribute (as the second value) and the attribute value
   *
   * @throws JsonProcessingException   if there is an error during the JSON parsing process
   * @throws TokenValidationException  if the disclosure format is invalid, i.e., the decoded
   *                                   and parsed data does not meet the expected structure
   */
  public Disclosure(String disclosureB64Url)
    throws JsonProcessingException, TokenValidationException {
    this.disclosure = new String(
      Base64.getUrlDecoder().decode(disclosureB64Url),
      StandardCharsets.UTF_8
    );
    List<Object> objectList = JSONUtils.JSON_MAPPER.readValue(
      this.disclosure,
      new TypeReference<>() {}
    );
    if (
      !(objectList.get(0) instanceof String) ||
      !(objectList.get(1) instanceof String)
    ) {
      throw new TokenValidationException("Invalid disclosure format");
    }
    switch (objectList.size()) {
      case 2:
        this.salt = (String) objectList.get(0);
        this.name = null;
        this.value = objectList.get(1);
        break;
      case 3:
        this.salt = (String) objectList.get(0);
        this.name = (String) objectList.get(1);
        this.value = objectList.get(2);
        break;
      default:
        throw new TokenValidationException("Invalid disclosure format");
    }
  }
}

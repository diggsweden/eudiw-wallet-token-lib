// SPDX-FileCopyrightText: 2024 Digg - Agency for Digital Government
//
// SPDX-License-Identifier: EUPL-1.2

package se.digg.wallet.datatypes.sdjwt.data;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.core.type.TypeReference;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.util.Base64;
import java.util.List;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;
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

  public static final SecureRandom RNG = new SecureRandom();

  private String salt;
  private String name;
  private Object value;
  private String disclosure;

  public Disclosure(TokenAttribute tokenAttribute)
    throws JsonProcessingException {
    this.salt = Base64.getUrlEncoder()
      .withoutPadding()
      .encodeToString(new BigInteger(128, RNG).toByteArray());
    this.name = tokenAttribute.getType() != null ? tokenAttribute.getType().getAttributeName() : null;
    this.value = tokenAttribute.getValue();
    this.disclosure = name != null
      ? JSONUtils.JSON_MAPPER.writeValueAsString(
        List.of(this.salt, this.name, this.value)
      )
      : JSONUtils.JSON_MAPPER.writeValueAsString(
        List.of(this.salt, this.value)
      );
  }

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

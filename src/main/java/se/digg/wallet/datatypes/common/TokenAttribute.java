// SPDX-FileCopyrightText: 2024 Digg - Agency for Digital Government
//
// SPDX-License-Identifier: EUPL-1.2

package se.digg.wallet.datatypes.common;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

/**
 * Represents a token attribute used in various token operations.
 * <p>
 * This class encapsulates an attribute with a specific type and value. The type
 * of the attribute is defined by {@link TokenAttributeType}, which specifies the
 * namespace and attribute name. The value is stored as an object, allowing flexibility
 * to represent various data types such as String, Integer, or LocalDate depending on the
 * context of the attribute.
 */
@Data
@AllArgsConstructor
@NoArgsConstructor
@Builder
public class TokenAttribute {

  /** The type of token attribute */
  private TokenAttributeType type;
  /** The attribute value. For most attributes, this is either a String, Integer or LocalDate object */
  private Object value;
}

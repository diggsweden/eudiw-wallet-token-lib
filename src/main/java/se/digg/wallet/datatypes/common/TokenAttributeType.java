// SPDX-FileCopyrightText: 2025 Digg - Agency for Digital Government
//
// SPDX-License-Identifier: EUPL-1.2

package se.digg.wallet.datatypes.common;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

/**
 * Represents a structured type for a token attribute, which can be used in various
 * token-related operations such as selective disclosure, validation, or issuance.
 *
 * This class encapsulates the namespace and the attribute name associated with
 * a specific token attribute. The namespace may define a specific scope or context,
 * while the attribute name identifies the attribute within that namespace. If the
 * namespace is not specified, only the attribute name is considered.
 */
@Data
@AllArgsConstructor
@NoArgsConstructor
public class TokenAttributeType {

  /** Optional name space for this attribute */
  private String nameSpace;
  /** The unique name of the attribute within its name space if applicable */
  private String attributeName;

  /**
   * Constructs a TokenAttributeType instance with the specified attribute name.
   *
   * @param attributeName the name of the token attribute to be associated with this type.
   *                       This parameter specifies the name of the attribute and it is
   *                       required while creating the instance. The namespace is set to null.
   */
  public TokenAttributeType(String attributeName) {
    this.attributeName = attributeName;
    this.nameSpace = null;
  }

  /** {@inheritDoc} */
  @Override
  public String toString() {
    if (nameSpace == null) {
      return attributeName;
    }
    return nameSpace + ":" + attributeName;
  }
}

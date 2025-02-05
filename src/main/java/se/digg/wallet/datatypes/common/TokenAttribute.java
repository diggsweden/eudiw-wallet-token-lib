// SPDX-FileCopyrightText: 2024 Digg - Agency for Digital Government
//
// SPDX-License-Identifier: EUPL-1.2

package se.digg.wallet.datatypes.common;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

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

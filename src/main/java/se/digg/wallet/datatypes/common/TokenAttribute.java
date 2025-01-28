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

  /** The name of the attribute presented in the token */
  private String name;
  /** Optional nameSpace declaration (Required for mDL tokens) */
  private String nameSpace;
  /** The attribute value. For most attributes, this is either a String, Integer or LocalDate object */
  private Object value;
}

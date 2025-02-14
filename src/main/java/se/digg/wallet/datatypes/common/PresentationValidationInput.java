// SPDX-FileCopyrightText: 2025 Digg - Agency for Digital Government
//
// SPDX-License-Identifier: EUPL-1.2

package se.digg.wallet.datatypes.common;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

/**
 * Input to presentation validation for mDoc and SD JWT
 */
@Data
@AllArgsConstructor
@NoArgsConstructor
public class PresentationValidationInput {

  /**
   * The nonce value provided in an OpenID4VP request
   */
  protected String requestNonce;
}

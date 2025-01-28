// SPDX-FileCopyrightText: 2024 Digg - Agency for Digital Government
//
// SPDX-License-Identifier: EUPL-1.2

package se.digg.wallet.datatypes.common;

import java.io.Serial;

/**
 * Exception thrown wile validating a token
 */
public class TokenValidationException extends Exception {

  @Serial
  private static final long serialVersionUID = -3706726881712381049L;

  /** {@inheritDoc} */
  public TokenValidationException(String message) {
    super(message);
  }

  /** {@inheritDoc} */
  public TokenValidationException(String message, Throwable cause) {
    super(message, cause);
  }
}

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

  /**
   * Constructs a new TokenValidationException with the specified detail message.
   *
   * @param message the detail message explaining the reason for the exception
   */
  public TokenValidationException(String message) {
    super(message);
  }

  /**
   * Constructs a new TokenValidationException with the specified detail message and cause.
   *
   * @param message the detail message explaining the reason for the exception
   * @param cause the cause of the exception, which can be retrieved later by the
   *        {@link Throwable#getCause()} method
   */
  public TokenValidationException(String message, Throwable cause) {
    super(message, cause);
  }
}

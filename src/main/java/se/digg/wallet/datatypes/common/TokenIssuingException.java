// SPDX-FileCopyrightText: 2024 Digg - Agency for Digital Government
//
// SPDX-License-Identifier: EUPL-1.2

package se.digg.wallet.datatypes.common;

import java.io.Serial;

/**
 * Exception caught while issuing a token
 */
public class TokenIssuingException extends Exception {

  @Serial
  private static final long serialVersionUID = -3234309120112902779L;

  /**
   * Constructs a new TokenIssuingException with the specified detail message.
   *
   * @param message the detail message explaining the reason for the exception
   */
  public TokenIssuingException(String message) {
    super(message);
  }

  /**
   * Constructs a new TokenIssuingException with the specified detail message and cause.
   *
   * @param message the detail message explaining the reason for the exception
   * @param cause the cause of the exception, which can be retrieved later using the {@code getCause()} method
   */
  public TokenIssuingException(String message, Throwable cause) {
    super(message, cause);
  }
}

// SPDX-FileCopyrightText: 2025 Digg - Agency for Digital Government
//
// SPDX-License-Identifier: EUPL-1.2

package se.digg.wallet.datatypes.common;

import java.io.Serial;

/**
 * A custom exception that is thrown when an error occurs during token parsing.
 *
 * This exception can be used to indicate issues such as invalid token structure,
 * parsing failures, or other errors encountered while processing a token.
 */
public class TokenParsingException extends Exception {

  @Serial
  private static final long serialVersionUID = -150091799709439631L;

  /**
   * Default constructor for the TokenParsingException class.
   *
   * This constructor creates a new instance of TokenParsingException without any
   * specific error message or cause. It is typically used when there is a token
   * parsing error that does not require additional context.
   */
  public TokenParsingException() {}

  /**
   * Constructs a new TokenParsingException with the specified detail message.
   *
   * @param message the detail message, which provides additional information
   *                about the token parsing error. This message is typically
   *                intended for debugging or logging purposes.
   */
  public TokenParsingException(String message) {
    super(message);
  }

  /**
   * Constructs a TokenParsingException with the specified detail message and cause.
   *
   * @param message the detail message, which provides additional context about the token parsing error.
   *                This message is typically useful for debugging or logging purposes.
   * @param cause the cause of the token parsing error. This can be another throwable that represents
   *              the underlying issue that led to this exception.
   */
  public TokenParsingException(String message, Throwable cause) {
    super(message, cause);
  }
}

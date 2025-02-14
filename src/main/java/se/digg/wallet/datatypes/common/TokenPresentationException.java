// SPDX-FileCopyrightText: 2025 Digg - Agency for Digital Government
//
// SPDX-License-Identifier: EUPL-1.2

package se.digg.wallet.datatypes.common;

import java.io.Serial;

/**
 * Exception thrown to indicate an error during the token presentation process.
 *
 * This exception is used in cases where the process of creating a verifiable token
 * presentation with selective disclosures fails due to invalid inputs, cryptographic
 * errors, or other issues that prevent successful presentation. It provides constructors
 * for specifying detailed error messages and causes.
 */
public class TokenPresentationException extends Exception {

  @Serial
  private static final long serialVersionUID = 942635978985209161L;

  /**
   * Default constructor for the TokenPresentationException.
   * This constructor initializes a new instance of the exception without any
   * specific message or cause, indicating a generic error during the token
   * presentation process.
   */
  public TokenPresentationException() {}

  /**
   * Constructs a new TokenPresentationException with the specified detail message.
   *
   * @param message the detail message, which provides additional information about the error
   */
  public TokenPresentationException(String message) {
    super(message);
  }

  /**
   * Constructs a new TokenPresentationException with the specified detail message and cause.
   *
   * @param message the detail message providing additional context about the error
   * @param cause the underlying cause of the exception, typically another throwable
   */
  public TokenPresentationException(String message, Throwable cause) {
    super(message, cause);
  }

  /**
   * Constructs a new TokenPresentationException with the specified cause.
   *
   * @param cause the underlying cause of this exception, typically another throwable
   */
  public TokenPresentationException(Throwable cause) {
    super(cause);
  }
}

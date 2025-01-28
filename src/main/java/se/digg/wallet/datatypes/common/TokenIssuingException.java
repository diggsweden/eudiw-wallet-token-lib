package se.digg.wallet.datatypes.common;

import java.io.Serial;

/**
 * Exception caugth while issuing a token
 */
public class TokenIssuingException extends Exception {
  @Serial private static final long serialVersionUID = -3234309120112902779L;

  /** {@inheritDoc} */
  public TokenIssuingException(String message) {
    super(message);
  }

  /** {@inheritDoc} */
  public TokenIssuingException(String message, Throwable cause) {
    super(message, cause);
  }
}

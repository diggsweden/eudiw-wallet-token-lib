package se.digg.wallet.datatypes.common;

import java.io.Serial;

public class TokenPresentationException extends Exception {
  @Serial
  private static final long serialVersionUID = 942635978985209161L;

  public TokenPresentationException() {
  }

  public TokenPresentationException(String message) {
    super(message);
  }

  public TokenPresentationException(String message, Throwable cause) {
    super(message, cause);
  }

  public TokenPresentationException(Throwable cause) {
    super(cause);
  }
}

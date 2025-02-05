package se.digg.wallet.datatypes.common;

import java.io.Serial;

public class TokenParsingException extends Exception {
  @Serial
  private static final long serialVersionUID = -150091799709439631L;


  public TokenParsingException() {
  }

  public TokenParsingException(String message) {
    super(message);
  }

  public TokenParsingException(String message, Throwable cause) {
    super(message, cause);
  }
}

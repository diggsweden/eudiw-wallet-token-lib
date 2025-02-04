package se.digg.wallet.datatypes.common;

import java.io.Serial;

public class TokenParsingexception extends Exception {
  @Serial
  private static final long serialVersionUID = -150091799709439631L;


  public TokenParsingexception() {
  }

  public TokenParsingexception(String message) {
    super(message);
  }

  public TokenParsingexception(String message, Throwable cause) {
    super(message, cause);
  }
}

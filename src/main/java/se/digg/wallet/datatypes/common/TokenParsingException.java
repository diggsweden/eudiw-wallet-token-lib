// SPDX-FileCopyrightText: 2025 Digg - Agency for Digital Government
//
// SPDX-License-Identifier: EUPL-1.2

package se.digg.wallet.datatypes.common;

import java.io.Serial;

public class TokenParsingException extends Exception {

  @Serial
  private static final long serialVersionUID = -150091799709439631L;

  public TokenParsingException() {}

  public TokenParsingException(String message) {
    super(message);
  }

  public TokenParsingException(String message, Throwable cause) {
    super(message, cause);
  }
}

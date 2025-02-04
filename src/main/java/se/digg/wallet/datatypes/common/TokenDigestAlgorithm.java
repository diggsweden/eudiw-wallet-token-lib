// SPDX-FileCopyrightText: 2024 Digg - Agency for Digital Government
//
// SPDX-License-Identifier: EUPL-1.2

package se.digg.wallet.datatypes.common;

import java.io.IOException;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;
import lombok.AllArgsConstructor;
import lombok.Getter;

/**
 * Hash algorithms supported by the mDL standard
 */
@Getter
@AllArgsConstructor
public enum TokenDigestAlgorithm {
  SHA_256("SHA-256", "SHA-256"),
  SHA_384("SHA-384", "SHA-384"),
  SHA_512("SHA-512", "SHA-512");

  private final String mdlName;
  private final String jdkName;

  public static TokenDigestAlgorithm fromMdlName(String mdlName)
    throws NoSuchAlgorithmException {
    return Arrays.stream(values())
      .filter(
        tokenDigestAlgorithm ->
          tokenDigestAlgorithm.getMdlName().equalsIgnoreCase(mdlName)
      )
      .findFirst()
      .orElseThrow(() -> new NoSuchAlgorithmException("Unsupported mDL hash algorithm"));
  }
}

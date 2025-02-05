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
  SHA_256("SHA-256", "SHA-256", "sha-256"),
  SHA_384("SHA-384", "SHA-384", "sha-384"),
  SHA_512("SHA-512", "SHA-512", "sha-512");

  private final String mdlName;
  private final String jdkName;
  private final String sdJwtName;

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

  public static TokenDigestAlgorithm fromSdJwtName(String sdJwtName) throws NoSuchAlgorithmException {
    return Arrays.stream(values())
      .filter(
        tokenDigestAlgorithm ->
          tokenDigestAlgorithm.getSdJwtName().equalsIgnoreCase(sdJwtName)
      )
      .findFirst()
      .orElseThrow(() -> new NoSuchAlgorithmException("Unsupported SD-JWT hash algorithm"));
  }

}

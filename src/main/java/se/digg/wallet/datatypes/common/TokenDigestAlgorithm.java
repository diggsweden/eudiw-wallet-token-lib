// SPDX-FileCopyrightText: 2024 Digg - Agency for Digital Government
//
// SPDX-License-Identifier: EUPL-1.2

package se.digg.wallet.datatypes.common;

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
  /** SHA 256 */
  SHA_256("SHA-256", "SHA-256", "sha-256"),
  /** SHA 384 */
  SHA_384("SHA-384", "SHA-384", "sha-384"),
  /** SHA 512 */
  SHA_512("SHA-512", "SHA-512", "sha-512");

  /** Name of hash algorithm used in mDL documents */
  private final String mdlName;
  /** Name of hash algorithm used in JDK MessageDigest instantiations */
  private final String jdkName;
  /** Name of hash algorithm used in SD JWT representations (sd_alg) */
  private final String sdJwtName;

  /**
   * Converts a given mDL hash algorithm name to a corresponding {@code TokenDigestAlgorithm} instance.
   *
   * @param mdlName the name of the hash algorithm as specified in mDL documents.
   * @return the corresponding {@code TokenDigestAlgorithm} instance.
   * @throws NoSuchAlgorithmException if the provided mDL hash algorithm name is not supported.
   */
  public static TokenDigestAlgorithm fromMdlName(String mdlName)
    throws NoSuchAlgorithmException {
    return Arrays.stream(values())
      .filter(
        tokenDigestAlgorithm ->
          tokenDigestAlgorithm.getMdlName().equalsIgnoreCase(mdlName)
      )
      .findFirst()
      .orElseThrow(
        () -> new NoSuchAlgorithmException("Unsupported mDL hash algorithm")
      );
  }

  /**
   * Converts a given SD-JWT hash algorithm name to a corresponding {@code TokenDigestAlgorithm} instance.
   *
   * @param sdJwtName the name of the hash algorithm as specified in SD-JWT representations.
   * @return the corresponding {@code TokenDigestAlgorithm} instance.
   * @throws NoSuchAlgorithmException if the provided SD-JWT hash algorithm name is not supported.
   */
  public static TokenDigestAlgorithm fromSdJwtName(String sdJwtName)
    throws NoSuchAlgorithmException {
    return Arrays.stream(values())
      .filter(
        tokenDigestAlgorithm ->
          tokenDigestAlgorithm.getSdJwtName().equalsIgnoreCase(sdJwtName)
      )
      .findFirst()
      .orElseThrow(
        () -> new NoSuchAlgorithmException("Unsupported SD-JWT hash algorithm")
      );
  }
}

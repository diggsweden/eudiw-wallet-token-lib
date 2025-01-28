package se.digg.wallet.datatypes.common;

import lombok.AllArgsConstructor;
import lombok.Getter;

import java.io.IOException;
import java.util.Arrays;

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

  public static TokenDigestAlgorithm fromMdlName(String mdlName) throws IOException {
    return Arrays.stream(values())
      .filter(tokenDigestAlgorithm -> tokenDigestAlgorithm.getMdlName().equalsIgnoreCase(mdlName))
      .findFirst()
      .orElseThrow(() -> new IOException("Unsupported mDL hash algorithm"));
  }
}

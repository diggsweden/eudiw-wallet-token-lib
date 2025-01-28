package se.digg.wallet.datatypes.common;

/**
 * Interface for a token issuer
 */
public interface TokenIssuer<T extends TokenInput> {

  /**
   * Generates a token based on the provided TokenInput.
   *
   * @param tokenInput the token input object containing attributes, issuer credential, expiration duration,
   *                   signing algorithm, and wallet public key
   * @return a byte array representing the issued token
   */
  byte[] issueToken(T tokenInput) throws TokenIssuingException;

}

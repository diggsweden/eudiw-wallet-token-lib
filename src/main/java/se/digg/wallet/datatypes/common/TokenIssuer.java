// SPDX-FileCopyrightText: 2024 Digg - Agency for Digital Government
//
// SPDX-License-Identifier: EUPL-1.2

package se.digg.wallet.datatypes.common;

/**
 * Represents a contract for issuing tokens based on input data.
 *
 * This interface defines the method necessary to generate a token given a set of inputs
 * provided by a class extending from {@link TokenInput}. Implementations of this interface
 * handle the process of token creation, including applying signing algorithms and
 * enforcing properties like issuer credentials, validity duration, and selective disclosure.
 *
 * @param <T> the type parameter extending {@link TokenInput}, encapsulating the data required
 *            to issue a token
 */
public interface TokenIssuer<T extends TokenInput> {
  /**
   * Generates a token based on the provided TokenInput.
   *
   * @param tokenInput the token input object containing attributes, issuer credential, expiration duration,
   *                   signing algorithm, and wallet public key
   * @return a byte array representing the issued token
   * @throws TokenIssuingException if an error occurs during token issuance
   */
  byte[] issueToken(T tokenInput) throws TokenIssuingException;
}

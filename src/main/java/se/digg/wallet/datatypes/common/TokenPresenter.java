// SPDX-FileCopyrightText: 2025 Digg - Agency for Digital Government
//
// SPDX-License-Identifier: EUPL-1.2

package se.digg.wallet.datatypes.common;

import java.security.PrivateKey;

/**
 * Represents an interface for creating verifiable presentation of a token with selective disclosures.
 * It defines the contract for handling a token issued by a token issuer and generating a
 * token with disclosures and cryptographic proof using a private key.
 *
 * @param <T> the type of PresentationInput, where the input contains the token,
 *            cryptographic settings, and disclosures.
 */
public interface TokenPresenter<T extends PresentationInput<?>> {
  /**
   * Creates a presentation token with selective disclosures
   *
   * @param presentationInput the verifiable presentation token input
   * @param privateKey the wallet private key used for generating device proof signature
   * @return token with disclosures and device provided key proof
   * @throws TokenPresentationException if the presentation process fails due to invalid input, cryptographic
   * errors, or any other processing issues
   */
  byte[] presentToken(
    PresentationInput<?> presentationInput,
    PrivateKey privateKey
  ) throws TokenPresentationException;
}

// SPDX-FileCopyrightText: 2025 Digg - Agency for Digital Government
//
// SPDX-License-Identifier: EUPL-1.2

package se.digg.wallet.datatypes.common;

import lombok.Getter;
import lombok.NoArgsConstructor;

/**
 * A generic class representing input data required for a presentation. This class is used to encapsulate
 * details such as tokens, cryptographic parameters, and disclosures that may be needed during the
 * presentation process.
 *
 * @param <T> the type of the disclosures associated with this presentation input
 */
@Getter
@NoArgsConstructor
public class PresentationInput<T> {

  /**
   * Represents a mDL or SD_JWT token in its serialized byte array form.
   */
  protected byte[] token;
  /**
   * Represents a unique cryptographic value associated with an operation or token to ensure
   * that it cannot be replayed.
   */
  protected String nonce;
  /**
   * Specifies the cryptographic algorithm to be used for wallet key binding proofs using the wallet private key
   */
  protected TokenSigningAlgorithm algorithm;
  /**
   * Represents disclosures that are used for selective data disclosure within
   * the context of a presentation.
   */
  protected T disclosures;
}

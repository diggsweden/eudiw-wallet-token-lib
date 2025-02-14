// SPDX-FileCopyrightText: 2024 Digg - Agency for Digital Government
//
// SPDX-License-Identifier: EUPL-1.2

package se.digg.wallet.datatypes.common;

import java.security.PublicKey;
import java.time.Duration;
import java.util.List;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;
import se.swedenconnect.security.credential.PkiCredential;

/**
 * Represents the input data required for issuing a token.
 */
@Data
@AllArgsConstructor
@NoArgsConstructor
@Builder
public class TokenInput {

  /** Issuer name */
  protected String issuer;
  /** Attributes enabled for selective disclosure */
  protected List<TokenAttribute> attributes;
  /** Attributes that appear in clear and do not require selective disclosure support */
  protected List<TokenAttribute> openAttributes;
  /** Issuing credential */
  protected PkiCredential issuerCredential;
  /** Validity Period */
  protected Duration expirationDuration;
  /** Signing algorithm */
  protected TokenSigningAlgorithm algorithm;
  /** Wallet public key */
  protected PublicKey walletPublicKey;
}

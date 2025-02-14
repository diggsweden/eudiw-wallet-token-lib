// SPDX-FileCopyrightText: 2024 Digg - Agency for Digital Government
//
// SPDX-License-Identifier: EUPL-1.2

package se.digg.wallet.datatypes.common;

import java.security.PublicKey;
import java.security.cert.X509Certificate;
import java.time.Instant;
import java.util.List;
import java.util.Map;
import lombok.Data;
import lombok.NoArgsConstructor;

/**
 * This class holds base result data for token validation. This is extended by explicit token validators
 */
@Data
@NoArgsConstructor
public class TokenValidationResult {

  /** Key used to validate the signature */
  protected PublicKey validationKey;
  /** Certificate used to validate the signature */
  protected X509Certificate validationCertificate;
  /** Certificate chain used to validate the signature */
  protected List<X509Certificate> validationChain;
  /** Wallet public key */
  protected PublicKey walletPublicKey;
  /** Issue time */
  protected Instant issueTime;
  /** Expiration time */
  protected Instant expirationTime;
  /** Nonce specified in presentation request */
  protected String presentationRequestNonce;
  /** A list of disclosed attribute values provided in a map with attribute type as key */
  protected Map<TokenAttributeType, Object> disclosedAttributes;
}

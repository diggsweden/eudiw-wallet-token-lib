// SPDX-FileCopyrightText: 2024 Digg - Agency for Digital Government
//
// SPDX-License-Identifier: EUPL-1.2

package se.digg.wallet.datatypes.common;

import java.security.PublicKey;
import java.security.cert.X509Certificate;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

/**
 * Information about a trusted key
 */
@Data
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class TrustedKey {

  private String keyId;
  private PublicKey publicKey;
  private X509Certificate certificate;
}

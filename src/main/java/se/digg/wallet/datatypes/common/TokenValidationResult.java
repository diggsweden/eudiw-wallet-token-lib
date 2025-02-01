// SPDX-FileCopyrightText: 2024 Digg - Agency for Digital Government
//
// SPDX-License-Identifier: EUPL-1.2

package se.digg.wallet.datatypes.common;

import java.security.PublicKey;
import java.security.cert.X509Certificate;
import java.util.List;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

/**
 * This is an abstract result class for token validation results. This may be extended by explicit token validators
 */
@Data
@NoArgsConstructor
public class TokenValidationResult{

  protected PublicKey validationKey;

  protected X509Certificate validationCertificate;

  protected List<X509Certificate> validationChain;

  protected PublicKey walletPublicKey;

}

package se.digg.wallet.datatypes.common;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.security.PublicKey;
import java.security.cert.X509Certificate;

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

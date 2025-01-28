package se.digg.wallet.datatypes.common;

import com.nimbusds.jose.JWSAlgorithm;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;
import se.swedenconnect.security.credential.PkiCredential;

import java.security.PublicKey;
import java.time.Duration;
import java.util.List;

@Data
@AllArgsConstructor
@NoArgsConstructor
@Builder
public class TokenInput {

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

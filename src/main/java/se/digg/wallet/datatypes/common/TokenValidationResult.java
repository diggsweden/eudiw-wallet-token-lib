package se.digg.wallet.datatypes.common;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.security.PublicKey;
import java.security.cert.X509Certificate;
import java.util.List;


/**
 * This is an abstract result class for token validation results. This may be extended by explicit token validators
 *
 * @param <T> Class Type for the Token as Java Object
 * @param <P> Class Type for the signed Payload as Java Object
 */
@Data
@NoArgsConstructor
public abstract class TokenValidationResult<T extends Object, P extends Object> {

  protected PublicKey validationKey;

  protected X509Certificate validationCertificate;

  protected List<X509Certificate> validationChain;

  protected PublicKey walletPublicKey;

  /**
   * Retrieves the validated token data.
   *
   * @return The token data.
   */
  public abstract T getTokenData();

  /**
   * Retrieves the signed payload associated with the token.
   *
   * @return The signed payload data.
   */
  public abstract P getTokenPayload();
}

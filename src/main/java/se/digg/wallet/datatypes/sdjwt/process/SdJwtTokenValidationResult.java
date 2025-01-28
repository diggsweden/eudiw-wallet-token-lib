package se.digg.wallet.datatypes.sdjwt.process;

import com.nimbusds.jose.Payload;
import lombok.Getter;
import lombok.Setter;
import se.digg.wallet.datatypes.common.TokenValidationResult;
import se.digg.wallet.datatypes.sdjwt.data.SdJwt;

/**
 * Extended validation results for SdJwt validation
 */
@Setter
public class SdJwtTokenValidationResult extends TokenValidationResult<SdJwt, Payload> {

  private SdJwt vcToken;
  private Payload disclosedTokenPayload;
  @Getter private boolean keyBindingProtection;

  @Override public SdJwt getTokenData() {
    return vcToken;
  }

  @Override public Payload getTokenPayload() {
    return disclosedTokenPayload;
  }
}

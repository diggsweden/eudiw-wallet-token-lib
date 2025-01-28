package se.digg.wallet.datatypes.mdl.process;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;
import se.digg.wallet.datatypes.common.TokenValidationResult;
import se.digg.wallet.datatypes.mdl.data.IssuerSigned;
import se.digg.wallet.datatypes.mdl.data.MobileSecurityObject;

/**
 * Description
 */
@Data
@AllArgsConstructor
@NoArgsConstructor
@Builder
public class MdlIssuerSignedValidationResult extends TokenValidationResult<IssuerSigned, MobileSecurityObject> {

  private IssuerSigned issuerSigned;
  private MobileSecurityObject mso;

  @Override public IssuerSigned getTokenData() {
    return null;
  }

  @Override public MobileSecurityObject getTokenPayload() {
    return null;
  }
}

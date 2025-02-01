package se.digg.wallet.datatypes.mdl.process;

import se.digg.wallet.datatypes.common.TokenValidationException;
import se.digg.wallet.datatypes.common.TokenValidationResult;
import se.digg.wallet.datatypes.common.TokenValidator;
import se.digg.wallet.datatypes.common.TrustedKey;

import java.util.List;

public class MdlPresentationValidator implements TokenValidator {
  @Override
  public TokenValidationResult validateToken(byte[] token, List<TrustedKey> trustedKeys) throws TokenValidationException {
    return null;
  }
}

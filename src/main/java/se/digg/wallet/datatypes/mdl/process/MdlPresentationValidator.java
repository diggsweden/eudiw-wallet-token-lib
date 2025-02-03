package se.digg.wallet.datatypes.mdl.process;

import se.digg.wallet.datatypes.common.*;

import java.util.List;

public class MdlPresentationValidator implements PresentationValidator {

  @Override
  public TokenValidationResult validatePresentation(byte[] presentation, PresentationValidationInput presentationValidationInput,
       List<TrustedKey> trustedKeys) throws TokenValidationException {



/*
    MdlIssuerSignedValidator issuerSignedValidator = new MdlIssuerSignedValidator();
    MdlIssuerSignedValidationResult issuerSignedValidationResult = issuerSignedValidator.validateToken(token, trustedKeys);
    issuerSignedValidationResult.getMso().getDeviceKeyInfo()
*/

    return null;
  }
}

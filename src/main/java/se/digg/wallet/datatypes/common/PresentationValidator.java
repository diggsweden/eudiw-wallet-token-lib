package se.digg.wallet.datatypes.common;

import java.util.List;

public interface PresentationValidator {

  TokenValidationResult validatePresentation(byte[] presentation, PresentationValidationInput presentationValidationInput,
    List<TrustedKey> trustedKeys) throws TokenValidationException, TokenParsingException;

}

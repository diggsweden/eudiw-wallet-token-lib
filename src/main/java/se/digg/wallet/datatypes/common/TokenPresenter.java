package se.digg.wallet.datatypes.common;

import java.io.IOException;
import java.security.PrivateKey;
import java.util.Collections;
import java.util.List;
import java.util.Map;

public interface TokenPresenter<T extends PresentationInput<?>> {

  /**
   * Creates a presentation token with selective disclosures
   *
   * @param presentationInput the token provided by the token issuer
   * @return token with disclosures and device provided key proof
   */
  byte[] presentToken(PresentationInput<?> presentationInput, PrivateKey privateKey) throws TokenPresentationException;

}

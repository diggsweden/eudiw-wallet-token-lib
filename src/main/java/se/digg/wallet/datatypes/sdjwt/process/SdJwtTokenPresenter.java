package se.digg.wallet.datatypes.sdjwt.process;

import com.nimbusds.jose.JOSEException;
import se.digg.wallet.datatypes.common.PresentationInput;
import se.digg.wallet.datatypes.common.TokenPresentationException;
import se.digg.wallet.datatypes.common.TokenPresenter;
import se.digg.wallet.datatypes.common.TokenValidationException;
import se.digg.wallet.datatypes.sdjwt.data.SdJwt;
import se.digg.wallet.datatypes.sdjwt.data.SdJwtPresentationInput;

import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.util.Objects;

/**
 * A concrete implementation of the {@link TokenPresenter} interface for creating verifiable
 * presentations using SdJwt tokens with selective disclosures.
 * <p>
 * This class is responsible for taking an SdJwt token along with its associated
 * input parameters (nonce, audience, algorithm, etc.) and producing a verifiable
 * presentation. The verifiable presentation is signed using the provided private key.
 */
public class SdJwtTokenPresenter implements TokenPresenter<SdJwtPresentationInput> {

  /**
   * Default constructor for the SdJwtTokenPresenter class.
   * <p>
   * This constructor initializes a new instance of the SdJwtTokenPresenter,
   * a concrete implementation of the TokenPresenter interface. The presenter
   * is used for generating verifiable presentations of SdJwt tokens with selective disclosures.
   * <p>
   * SdJwtTokenPresenter is typically used in scenarios where verifiable credentials
   * need to be presented in a secure and signed format, ensuring compliance with selective
   * disclosure mechanisms.
   */
  public SdJwtTokenPresenter() {
  }

  @Override
  public byte[] presentToken(PresentationInput<?> presentationInput, PrivateKey privateKey) throws TokenPresentationException {

    if (presentationInput instanceof SdJwtPresentationInput input) {
      try {
        Objects.requireNonNull(input.getToken(), "Input token must not be null");
        Objects.requireNonNull(privateKey, "Private key must not be null");
        Objects.requireNonNull(input.getAlgorithm(), "Algorithm must not be null");
        Objects.requireNonNull(input.getAudience(), "Audience must not be null");
        Objects.requireNonNull(input.getNonce(), "Nonce must not be null");

        SdJwt sdJwt = SdJwt.parse(new String(presentationInput.getToken()));
        String protectedVerifiablePresentation = sdJwt.protectedPresentation(
          input.getAlgorithm().jwsSigner(privateKey),
          input.getAlgorithm().getJwsAlgorithm(),
          input.getAudience(),
          input.getNonce(),
          input.getDisclosures()
        );
        return protectedVerifiablePresentation.getBytes();
      }
      catch (TokenValidationException | JOSEException | NoSuchAlgorithmException e) {
        throw new TokenPresentationException("Unable to create verifiable presentation",e);
      }
      catch (Exception e) {
        throw new TokenPresentationException("Critical error while creating verifiable presentation",e);
      }
    } else {
      throw new TokenPresentationException("PresentationInput must be of type SdJwtPresentationInput");
    }
  }
}

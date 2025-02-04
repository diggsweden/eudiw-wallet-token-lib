package se.digg.wallet.datatypes.mdl.process;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.upokecenter.cbor.CBORObject;
import lombok.extern.slf4j.Slf4j;
import org.bouncycastle.util.encoders.Hex;
import se.digg.wallet.datatypes.common.*;
import se.digg.wallet.datatypes.mdl.data.*;
import se.idsec.cose.COSEObjectTag;
import se.idsec.cose.CoseException;
import se.idsec.cose.Sign1COSEObject;

import java.time.Duration;
import java.util.List;

/**
 * Implementation of the {@link PresentationValidator} interface that validates
 * presentations of Mobile Driver's Licenses (mDLs).
 * <p>
 * This class performs mDL-specific validation, ensuring the presentation data is valid,
 * the issuer's signature is authenticated, and the device signature is correctly verified.
 * <p>
 * The validation flow includes the following steps:
 * - Parsing the mDL presentation data
 * - Validating the issuer's signed data against the provided trusted keys
 * - Reconstructing and verifying the device signature
 * - Returning a validation result that includes the validation key, certificate chain,
 *   and other relevant data
 * <p>
 * Logging behavior:
 * - Detailed trace logs of the presentation data when tracing is enabled
 * - Debug-level logs to denote the progress and key validation outcomes
 * <p>
 * Exceptions:
 * - Throws {@link TokenValidationException} for invalid input or validation failures
 * - Throws {@link TokenParsingException} for errors encountered during parsing
 */
@Slf4j
public class MdlPresentationValidator implements PresentationValidator {

  private final Duration timeSkew;

  public MdlPresentationValidator() {
    this(Duration.ofSeconds(30));
  }

  public MdlPresentationValidator(Duration timeSkew) {
    this.timeSkew = timeSkew;
  }

  /**
   * Validates an mDL (Mobile Driver's License) presentation against a specified validation input
   * and a list of trusted keys.
   *
   * @param presentation a byte array representing the mDL presentation data to be validated
   * @param presentationValidationInput an instance of {@link PresentationValidationInput}, expected to be of type
   *        {@code MdlPresentationValidationInput}, containing validation input parameters and session context
   * @param trustedKeys a list of {@link TrustedKey} objects representing the trusted keys for validation
   * @return a {@link TokenValidationResult} representing the result of validating the presentation
   * @throws TokenValidationException if the presentation or input data are invalid
   * @throws TokenParsingException if there are errors in parsing the token data
   */
  @Override
  public TokenValidationResult validatePresentation(byte[] presentation, PresentationValidationInput presentationValidationInput,
       List<TrustedKey> trustedKeys) throws TokenValidationException, TokenParsingException {

    if (log.isTraceEnabled()) {
      log.trace("Validating mDL presentation:\n{}", Hex.toHexString(presentation));
    } else {
      log.debug("Validating mDL presentation");
    }

    // Check input type
    if (!(presentationValidationInput instanceof MdlPresentationValidationInput input)) {
      throw new TokenValidationException("Presentation validation input of MDL presentations must be of type " +
        "MdlPresentationValidationInput");
    }

    try {
      // Parse input presentation data
      DeviceResponse deviceResponse = DeviceResponse.deserialize(presentation);
      // Parse and validate the issuer signed data
      IssuerSigned issuerSigned = deviceResponse.getIssuerSigned();
      byte[] issuerSignedBytes = CBORUtils.CBOR_MAPPER.writeValueAsBytes(issuerSigned);
      MdlIssuerSignedValidator issuerSignedValidator = new MdlIssuerSignedValidator(timeSkew);
      MdlIssuerSignedValidationResult issuerSignedValidationResult = issuerSignedValidator.validateToken(issuerSignedBytes, trustedKeys);
      // For now only accept device signatures
      if (deviceResponse.getDeviceMac() != null) {
        // TODO support device Mac authentication
        log.debug("This presentation has a device mac. This is not supported yet and ignored");
      }
      if (deviceResponse.getDeviceSignature() == null) {
        // As we only support device signature. One must be available
        throw new TokenValidationException("Token presentation must have a device signature");
      }
      // Get the detached device signature
      CBORObject deviceSignatureObject = CBORObject.DecodeFromBytes(deviceResponse.getDeviceSignature());
      // Reconstruct the detached data
      DeviceAuthentication deviceAuthentication = new DeviceAuthentication(
        deviceResponse.getDocType(),
        new SessionTranscript(
          input.getClientId(),
          input.getResponseUri(),
          input.getRequestNonce(),
          input.getMdocGeneratedNonce()
        )
      );
      // Insert the detached data as payload
      deviceSignatureObject.set(2, CBORObject.FromByteArray(deviceAuthentication.getDeviceAuthenticationBytes()));
      // Create the signed object with the restored payload
      Sign1COSEObject sign1COSEObject = (Sign1COSEObject) Sign1COSEObject.DecodeFromBytes(
        deviceSignatureObject.EncodeToBytes(),
        COSEObjectTag.Sign1);
      // Get the device key
      MobileSecurityObject.DeviceKeyInfo deviceKeyInfo = issuerSignedValidationResult.getMso().getDeviceKeyInfo();
      // Validate signature against device key
      boolean deviceSignatureValid = sign1COSEObject.validate(deviceKeyInfo.getDeviceKey());
      if (!deviceSignatureValid) {
        // Device signature was invalid
        throw new TokenValidationException("Device signature is invalid");
      }
      // Signature is valid. Provide result data
      log.debug("Device signature is valid");
      issuerSignedValidationResult.setPresentationRequestNonce(input.getRequestNonce());
      MdlPresentationValidationResult result = new MdlPresentationValidationResult(
        issuerSignedValidationResult,
        deviceResponse.getDocType(),
        deviceResponse.getStatus(),
        deviceResponse.getVersion()
      );
      result.setPresentationRequestNonce(input.getRequestNonce());
      return result;
    } catch (JsonProcessingException | CoseException e) {
      throw new TokenParsingException("Error parsing token data",e);
    } catch (Exception e) {
      throw new TokenValidationException("Error validating the mDL presentation token", e);
    }
  }
}

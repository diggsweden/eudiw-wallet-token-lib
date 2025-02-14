// SPDX-FileCopyrightText: 2025 Digg - Agency for Digital Government
//
// SPDX-License-Identifier: EUPL-1.2

package se.digg.wallet.datatypes.mdl.process;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.upokecenter.cbor.CBORObject;
import java.time.Duration;
import java.util.List;
import java.util.Map;
import lombok.extern.slf4j.Slf4j;
import org.bouncycastle.util.encoders.Hex;
import se.digg.cose.COSEObjectTag;
import se.digg.cose.CoseException;
import se.digg.cose.MAC0COSEObject;
import se.digg.cose.Sign1COSEObject;
import se.digg.wallet.datatypes.common.PresentationValidationInput;
import se.digg.wallet.datatypes.common.PresentationValidator;
import se.digg.wallet.datatypes.common.TokenAttributeType;
import se.digg.wallet.datatypes.common.TokenParsingException;
import se.digg.wallet.datatypes.common.TokenValidationException;
import se.digg.wallet.datatypes.common.TokenValidationResult;
import se.digg.wallet.datatypes.common.TrustedKey;
import se.digg.wallet.datatypes.mdl.data.CBORUtils;
import se.digg.wallet.datatypes.mdl.data.DeviceAuthentication;
import se.digg.wallet.datatypes.mdl.data.DeviceResponse;
import se.digg.wallet.datatypes.mdl.data.IssuerSigned;
import se.digg.wallet.datatypes.mdl.data.IssuerSignedItem;
import se.digg.wallet.datatypes.mdl.data.MdlPresentationValidationInput;
import se.digg.wallet.datatypes.mdl.data.MobileSecurityObject;
import se.digg.wallet.datatypes.mdl.data.SessionTranscript;

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

  /** The maximum allowed time deviation (Duration) for verifying the validity of the data */
  private final Duration timeSkew;

  /**
   * Constructs a new instance of the MdlPresentationValidator with a default timeout duration of 30 seconds.
   */
  public MdlPresentationValidator() {
    this(Duration.ofSeconds(30));
  }

  /**
   * Constructs a new instance of the MdlPresentationValidator with the specified time skew.
   *
   * @param timeSkew the maximum allowed time deviation (Duration) for verifying the validity of the data.
   */
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
  public MdlPresentationValidationResult validatePresentation(
    byte[] presentation,
    PresentationValidationInput presentationValidationInput,
    List<TrustedKey> trustedKeys
  ) throws TokenValidationException, TokenParsingException {
    if (log.isTraceEnabled()) {
      log.trace(
        "Validating mDL presentation:\n{}",
        Hex.toHexString(presentation)
      );
    } else {
      log.debug("Validating mDL presentation");
    }

    // Check input type
    if (
      !(presentationValidationInput instanceof
        MdlPresentationValidationInput input)
    ) {
      throw new TokenValidationException(
        "Presentation validation input of MDL presentations must be of type " +
        "MdlPresentationValidationInput"
      );
    }

    try {
      // Parse input presentation data
      DeviceResponse deviceResponse = DeviceResponse.deserialize(presentation);
      // Parse and validate the issuer signed data
      IssuerSigned issuerSigned = deviceResponse.getIssuerSigned();
      byte[] issuerSignedBytes = CBORUtils.CBOR_MAPPER.writeValueAsBytes(
        issuerSigned
      );
      MdlIssuerSignedValidator issuerSignedValidator =
        new MdlIssuerSignedValidator(timeSkew);
      MdlIssuerSignedValidationResult issuerSignedValidationResult =
        issuerSignedValidator.validateToken(issuerSignedBytes, trustedKeys);
      // Ensure that device MAC or signature is present
      if (deviceResponse.getDeviceMac() == null && deviceResponse.getDeviceSignature() == null) {
        throw new TokenValidationException(
          "Token presentation must name device mac or device signature"
        );
      }
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
      // Get the wallet device key
      MobileSecurityObject.DeviceKeyInfo deviceKeyInfo =
        issuerSignedValidationResult.getMso().getDeviceKeyInfo();

      // Validate MAC if present
      if (deviceResponse.getDeviceMac() != null) {
        if (input.getClientPrivateKey() == null) {
          throw new TokenValidationException(
            "Client private key must be provided for MAC validation"
          );
        }
        CBORObject deviceMacObject = CBORObject.DecodeFromBytes(
          deviceResponse.getDeviceMac()
        );
        // Insert the detached data as payload
        deviceMacObject.set(
          2,
          CBORObject.FromByteArray(
            deviceAuthentication.getDeviceAuthenticationBytes()
          )
        );
        MAC0COSEObject mac0COSEObject =
          (MAC0COSEObject) MAC0COSEObject.DecodeFromBytes(
            deviceMacObject.EncodeToBytes(),
            COSEObjectTag.MAC0
          );
        boolean validMac = mac0COSEObject.Validate(CBORUtils.deriveEMacKey(
          CBORUtils.deriveSharedSecret(input.getClientPrivateKey(), deviceKeyInfo.getDeviceKey().AsPublicKey()),
          deviceAuthentication.getDeviceAuthenticationBytes()
        ));
        if (!validMac) {
          // Device signature was invalid
          throw new TokenValidationException("Device signature is invalid");
        }
        log.debug("Device MAC is valid");
      }
      // Validate device signature if present
      if (deviceResponse.getDeviceSignature() != null) {
        // Get the detached device signature
        CBORObject deviceSignatureObject = CBORObject.DecodeFromBytes(
          deviceResponse.getDeviceSignature()
        );
        // Insert the detached data as payload
        deviceSignatureObject.set(
          2,
          CBORObject.FromByteArray(
            deviceAuthentication.getDeviceAuthenticationBytes()
          )
        );
        // Create the signed object with the restored payload
        Sign1COSEObject sign1COSEObject =
          (Sign1COSEObject) Sign1COSEObject.DecodeFromBytes(
            deviceSignatureObject.EncodeToBytes(),
            COSEObjectTag.Sign1
          );
        // Validate signature against device key
        boolean deviceSignatureValid = sign1COSEObject.validate(
          deviceKeyInfo.getDeviceKey()
        );
        if (!deviceSignatureValid) {
          // Device signature was invalid
          throw new TokenValidationException("Device signature is invalid");
        }
        // Signature is valid. Provide result data
        log.debug("Device signature is valid");
      }
      // Retrieve disclosed signatures
      Map<TokenAttributeType, Object> disclosedAttributes =
        getDisclosedAttributes(issuerSigned.getNameSpaces());
      issuerSignedValidationResult.setPresentationRequestNonce(
        input.getRequestNonce()
      );
      MdlPresentationValidationResult result =
        new MdlPresentationValidationResult(
          issuerSignedValidationResult,
          deviceResponse.getDocType(),
          deviceResponse.getStatus(),
          deviceResponse.getVersion(),
          disclosedAttributes
        );
      result.setPresentationRequestNonce(input.getRequestNonce());
      return result;
    } catch (JsonProcessingException | CoseException e) {
      throw new TokenParsingException("Error parsing token data", e);
    } catch (Exception e) {
      throw new TokenValidationException(
        "Error validating the mDL presentation token",
        e
      );
    }
  }

  private Map<TokenAttributeType, Object> getDisclosedAttributes(
    Map<String, List<IssuerSignedItem>> nameSpaces
  ) {
    Map<TokenAttributeType, Object> disclosedAttributes =
      new java.util.HashMap<>();
    if (nameSpaces == null || nameSpaces.isEmpty()) {
      return disclosedAttributes;
    }
    nameSpaces.forEach((namespace, nsAttributes) -> {
      if (nsAttributes != null) {
        nsAttributes.forEach(issuerSignedItem -> {
          disclosedAttributes.put(
            new TokenAttributeType(
              namespace,
              issuerSignedItem.getElementIdentifier()
            ),
            issuerSignedItem.getElementValue()
          );
        });
      }
    });
    return disclosedAttributes;
  }
}

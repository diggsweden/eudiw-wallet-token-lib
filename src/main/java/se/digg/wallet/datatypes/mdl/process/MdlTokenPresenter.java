package se.digg.wallet.datatypes.mdl.process;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.upokecenter.cbor.CBORObject;
import se.digg.wallet.datatypes.common.*;
import se.digg.wallet.datatypes.mdl.data.*;
import se.digg.cose.*;

import java.io.IOException;
import java.security.PrivateKey;
import java.security.cert.CertificateEncodingException;
import java.util.List;
import java.util.Map;

/**
 * MdlTokenPresenter is an implementation of the {@code TokenPresenter} interface
 * specialized for processing mDL (mobile Driver's License) tokens. This class is responsible
 * for verifying the provided mDL token, applying selective disclosures, and producing
 * a cryptographically signed response suitable for presentation.
 *
 * The class validates the token and disclosures provided in the {@code MdlPresentationInput},
 * ensures the integrity of the token data, and generates a presentation response using the given
 * wallet private key. Additionally, it utilizes namespaces and selective disclosures to construct a
 * tailored response based on the disclosed attributes, ensuring privacy and compliance with the
 * specifications.
 */
public class MdlTokenPresenter implements TokenPresenter<MdlPresentationInput> {


  /**
   * Default constructor for the MdlTokenPresenter class.
   */
  public MdlTokenPresenter() {
  }

  /** {@inheritDoc} */
  @Override
  public byte[] presentToken(PresentationInput<?> presentationInput, PrivateKey privateKey) throws TokenPresentationException {

    if (presentationInput instanceof MdlPresentationInput input) {
      try {
        IssuerSigned issuerSigned = IssuerSigned.deserialize(input.getToken());
        Map<String, List<IssuerSignedItem>> nameSpaces = issuerSigned.getNameSpaces();
        Map<String, List<IssuerSignedItem>> disclosedNameSpaces = getDisclosedNameSpaces(nameSpaces, input.getDisclosures());
        issuerSigned.setNameSpaces(disclosedNameSpaces);

        MdlIssuerSignedValidator issuerSignedValidator = new MdlIssuerSignedValidator();
        MdlIssuerSignedValidationResult result = issuerSignedValidator.validateToken(input.getToken(), null);
        String docType = result.getMso().getDocType();
        DeviceAuthentication deviceAuthentication = new DeviceAuthentication(
          docType, new SessionTranscript(
            input.getClientId(), input.getResponseUri(), input.getNonce(), input.getMdocGeneratedNonce())
        );

        COSEKey key = new COSEKey(null, privateKey);
        Sign1COSEObject signedCOSEObject = CBORUtils.sign(deviceAuthentication.getDeviceAuthenticationBytes(), key, input.getAlgorithm().getAlgorithmID(),
          null, null, false);
        signedCOSEObject.SetContent((byte[]) null);
        CBORObject deviceSignature = signedCOSEObject.EncodeToCBORObject();

        DeviceResponse deviceResponse = new DeviceResponse(docType, issuerSigned, deviceSignature.EncodeToBytes());
        return CBORUtils.CBOR_MAPPER.writeValueAsBytes(deviceResponse);

      }
      catch (TokenParsingException | TokenValidationException | CoseException | CertificateEncodingException e) {
        throw new TokenPresentationException("Error presenting token", e);
      }
      catch (NullPointerException e) {
        throw new TokenPresentationException("Missing required input", e);
      } catch (JsonProcessingException e) {
        throw new TokenPresentationException("Error serializing token", e);
      }
    } else {
      throw new TokenPresentationException("PresentationInput must be of type MdlPresentationInput");
    }
  }

  /**
   * Filters and returns a subset of the provided namespaces based on the disclosed element identifiers.
   *
   * @param nameSpaces a map where keys represent namespace names, and values are lists of IssuerSignedItem instances representing signed attributes in those namespaces
   * @param disclosures a map where keys represent namespace names, and values are lists of attribute name identifiers that should be disclosed
   * @return a map containing only the entries from the input nameSpaces that match the disclosed namespaces and element identifiers provided in disclosures
   */
  private Map<String, List<IssuerSignedItem>> getDisclosedNameSpaces(Map<String, List<IssuerSignedItem>> nameSpaces, Map<String, List<String>> disclosures) {
    if (disclosures == null || disclosures.isEmpty()) {
      return nameSpaces;
    }
    Map<String, List<IssuerSignedItem>> disclosedNameSpaces = new java.util.HashMap<>();
    disclosures.forEach((key, value) -> {
      if (nameSpaces.containsKey(key)) {
        List<IssuerSignedItem> items = nameSpaces.get(key);
        List<IssuerSignedItem> disclosedItems = items.stream()
          .filter(item -> value.contains(item.getElementIdentifier()))
          .toList();
        disclosedNameSpaces.put(key, disclosedItems);
      }
    });
    return disclosedNameSpaces;
  }
}

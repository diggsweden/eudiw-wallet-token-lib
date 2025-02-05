package se.digg.wallet.datatypes.mdl.process;

import com.upokecenter.cbor.CBORObject;
import se.digg.wallet.datatypes.common.*;
import se.digg.wallet.datatypes.mdl.data.*;
import se.idsec.cose.*;

import java.io.IOException;
import java.security.PrivateKey;
import java.security.cert.CertificateEncodingException;
import java.util.List;
import java.util.Map;

public class MdlTokenPresenter implements TokenPresenter<MdlPresentationInput> {


  public MdlTokenPresenter() {
  }

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

      } catch (IOException | TokenParsingException | TokenValidationException | CoseException | CertificateEncodingException e) {
        throw new TokenPresentationException("Error presenting token", e);
      }
    } else {
      throw new TokenPresentationException("PresentationInput must be of type MdlPresentationInput");
    }
  }

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

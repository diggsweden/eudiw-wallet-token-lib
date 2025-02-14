// SPDX-FileCopyrightText: 2024 Digg - Agency for Digital Government
//
// SPDX-License-Identifier: EUPL-1.2

package se.digg.wallet.datatypes.mdl.process;

import com.fasterxml.jackson.core.JsonProcessingException;
import java.io.IOException;
import java.math.BigInteger;
import java.security.cert.CertificateEncodingException;
import java.util.*;
import lombok.Setter;
import org.bouncycastle.crypto.CryptoServicesRegistrar;
import se.digg.cose.CoseException;
import se.digg.wallet.datatypes.common.TokenAttribute;
import se.digg.wallet.datatypes.common.TokenInput;
import se.digg.wallet.datatypes.common.TokenIssuer;
import se.digg.wallet.datatypes.common.TokenIssuingException;
import se.digg.wallet.datatypes.mdl.data.CBORUtils;
import se.digg.wallet.datatypes.mdl.data.IssuerSigned;
import se.digg.wallet.datatypes.mdl.data.IssuerSignedItem;

/**
 * mDL token issuer implementing the common TokenIssuer interface producing the IssuerSigned part
 * of a complete mDoc verifiable presentation
 */
public class MdlTokenIssuer implements TokenIssuer<TokenInput> {

  /** Random source for hash salts */
  private static final Random RNG = CryptoServicesRegistrar.getSecureRandom();

  /** mDL version for this token issuer */
  private static final String MDL_VERSION = "1.0";
  /** docType declaration */
  private final String docType;
  /** Determines if a kid will be set based on getName() from the issuer credential */
  private final boolean setKid;

  /** Determines if a kid should be inserted in a protected header, default false */
  @Setter
  boolean kidInProtectedHeader;

  /**
   * Initializes a new instance of the MdlTokenIssuer class with default values.
   */
  public MdlTokenIssuer() {
    this.docType = "eu.europa.ec.eudi.pid.1";
    this.setKid = false;
    this.kidInProtectedHeader = false;
  }

  /**
   * Initializes a MdlTokenIssuer object with the provided setKid flag and document type.
   *
   * @param setKid a boolean flag indicating whether to set the key ID from signer credentials in the COSE signature
   * @param docType a String representing the document type
   */
  public MdlTokenIssuer(boolean setKid, String docType) {
    this.setKid = setKid;
    this.docType = docType;
    this.kidInProtectedHeader = false;
  }

  /**
   * Initializes a MdlTokenIssuer object with the provided setKid flag.
   *
   * @param setKid a boolean flag indicating whether to set the key ID from signer credentials in the COSE signature
   */
  public MdlTokenIssuer(boolean setKid) {
    this.docType = "eu.europa.ec.eudi.pid.1";
    this.kidInProtectedHeader = false;
    this.setKid = setKid;
  }

  /** {@inheritDoc} */
  @Override
  public byte[] issueToken(TokenInput tokenInput) throws TokenIssuingException {
    try {
      Map<String, List<IssuerSignedItem>> nameSpaces = getAttributes(
        tokenInput
      );
      IssuerSigned issuerSigned = IssuerSigned.builder()
        .namespaces(nameSpaces)
        .issuerAuthInput(
          tokenInput.getIssuerCredential(),
          tokenInput.getAlgorithm(),
          tokenInput.getWalletPublicKey(),
          tokenInput.getExpirationDuration(),
          docType,
          MDL_VERSION,
          setKid ? tokenInput.getIssuerCredential().getName() : null
        )
        .build();
      return CBORUtils.CBOR_MAPPER.writeValueAsBytes(issuerSigned);
    } catch (JsonProcessingException e) {
      throw new TokenIssuingException(
        "Data serialization error - Failed to issue token",
        e
      );
    } catch (CoseException e) {
      throw new TokenIssuingException(
        "Token signing error - Failed to issue token",
        e
      );
    } catch (CertificateEncodingException e) {
      throw new TokenIssuingException(
        "Illegal certificate information - Failed to issue token",
        e
      );
    } catch (IOException e) {
      throw new TokenIssuingException("Error issuing token", e);
    } catch (NullPointerException e) {
      throw new TokenIssuingException("Missing required input parameters", e);
    }
  }

  /**
   * Retrieves attributes from the provided TokenInput object and adds salt values and digest ID.
   *
   * @param tokenInput the TokenInput object containing attributes
   * @return a map of attribute namespaces to lists of IssuerSignedItem objects
   * @throws TokenIssuingException if there are issues with token issuance
   */
  private Map<String, List<IssuerSignedItem>> getAttributes(
    TokenInput tokenInput
  ) throws TokenIssuingException {
    List<TokenAttribute> inputAttributes = tokenInput.getAttributes();
    if (inputAttributes == null || inputAttributes.isEmpty()) {
      throw new TokenIssuingException(
        "No attributes provided for token issuance"
      );
    }
    if (
      tokenInput.getOpenAttributes() != null &&
      !tokenInput.getOpenAttributes().isEmpty()
    ) {
      throw new TokenIssuingException(
        "Open attributes are not supported for mDL token issuance"
      );
    }
    Map<String, List<IssuerSignedItem>> nameSpaces = new HashMap<>();
    for (int i = 0; i < inputAttributes.size(); i++) {
      TokenAttribute attribute = inputAttributes.get(i);
      IssuerSignedItem issuerSignedItem = IssuerSignedItem.builder()
        .digestID(i)
        .random(new BigInteger(128, RNG).toByteArray())
        .elementIdentifier(attribute.getType().getAttributeName())
        .elementValue(attribute.getValue())
        .build();
      nameSpaces
        .computeIfAbsent(
          attribute.getType().getNameSpace(),
          k -> new ArrayList<>()
        )
        .add(issuerSignedItem);
    }
    return nameSpaces;
  }
}

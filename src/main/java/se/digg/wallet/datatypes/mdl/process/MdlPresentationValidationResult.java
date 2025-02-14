// SPDX-FileCopyrightText: 2025 Digg - Agency for Digital Government
//
// SPDX-License-Identifier: EUPL-1.2

package se.digg.wallet.datatypes.mdl.process;

import java.util.Map;
import lombok.Data;
import lombok.EqualsAndHashCode;
import lombok.NoArgsConstructor;
import se.digg.wallet.datatypes.common.TokenAttributeType;

/**
 * Represents the result of validation for an mDL (Mobile Driving License) presentation.
 * This class extends the {@code MdlIssuerSignedValidationResult} and includes additional
 * fields to capture specific information and status relevant to the mDL presentation.
 */
@EqualsAndHashCode(callSuper = true)
@Data
@NoArgsConstructor
public class MdlPresentationValidationResult
  extends MdlIssuerSignedValidationResult {

  /**
   * Constructs a new instance of MdlPresentationValidationResult with specified parameters.
   *
   * @param issuerSignedValidationResult the issuer-signed validation result containing validation key,
   *                                     certificate, chain, wallet public key, issue time, expiration time,
   *                                     presentation request nonce, issuer signed data, and Mobile Security Object (MSO).
   * @param docType the document type of the Mobile Driving License (mDL) presentation
   * @param status the status code representing the validation result of the mDL presentation
   * @param version the version of the mDL presentation
   * @param disclosedAttributes a map of attributes disclosed during the validation, where the key is the
   *                            attribute type and the value is the attribute's value
   */
  public MdlPresentationValidationResult(
    MdlIssuerSignedValidationResult issuerSignedValidationResult,
    String docType,
    int status,
    String version,
    Map<TokenAttributeType, Object> disclosedAttributes
  ) {
    super();
    this.setValidationKey(issuerSignedValidationResult.getValidationKey());
    this.setValidationCertificate(
        issuerSignedValidationResult.getValidationCertificate()
      );
    this.setValidationChain(issuerSignedValidationResult.getValidationChain());
    this.setWalletPublicKey(issuerSignedValidationResult.getWalletPublicKey());
    this.setIssueTime(issuerSignedValidationResult.getIssueTime());
    this.setExpirationTime(issuerSignedValidationResult.getExpirationTime());
    this.setPresentationRequestNonce(
        issuerSignedValidationResult.getPresentationRequestNonce()
      );
    this.setIssuerSigned(issuerSignedValidationResult.getIssuerSigned());
    this.setMso(issuerSignedValidationResult.getMso());
    this.setDisclosedAttributes(disclosedAttributes);
    this.docType = docType;
    this.status = status;
    this.version = version;
  }

  /** Document type identifier */
  String docType;
  /** Status (always 0 on success) */
  int status;
  /** Version (shall be 1.0) */
  String version;
}

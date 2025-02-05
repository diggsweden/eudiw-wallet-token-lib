package se.digg.wallet.datatypes.mdl.process;

import lombok.Data;
import lombok.EqualsAndHashCode;
import lombok.NoArgsConstructor;

@EqualsAndHashCode(callSuper = true)
@Data
@NoArgsConstructor
public class MdlPresentationValidationResult extends MdlIssuerSignedValidationResult {

  public MdlPresentationValidationResult(MdlIssuerSignedValidationResult issuerSignedValidationResult,
       String docType, int status, String version) {
    super();
    this.setValidationKey(issuerSignedValidationResult.getValidationKey());
    this.setValidationCertificate(issuerSignedValidationResult.getValidationCertificate());
    this.setValidationChain(issuerSignedValidationResult.getValidationChain());
    this.setWalletPublicKey(issuerSignedValidationResult.getWalletPublicKey());
    this.setIssueTime(issuerSignedValidationResult.getIssueTime());
    this.setExpirationTime(issuerSignedValidationResult.getExpirationTime());
    this.setPresentationRequestNonce(issuerSignedValidationResult.getPresentationRequestNonce());
    this.setIssuerSigned(issuerSignedValidationResult.getIssuerSigned());
    this.setMso(issuerSignedValidationResult.getMso());
    this.docType = docType;
    this.status = status;
    this.version = version;
  }

  String docType;
  int status;
  String version;
}

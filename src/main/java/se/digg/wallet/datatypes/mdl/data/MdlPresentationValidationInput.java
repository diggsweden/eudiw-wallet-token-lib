package se.digg.wallet.datatypes.mdl.data;

import lombok.Data;
import lombok.EqualsAndHashCode;
import lombok.NoArgsConstructor;
import se.digg.wallet.datatypes.common.PresentationInput;
import se.digg.wallet.datatypes.common.PresentationValidationInput;

@EqualsAndHashCode(callSuper = true)
@Data
@NoArgsConstructor
public class MdlPresentationValidationInput extends PresentationValidationInput {

  public MdlPresentationValidationInput(MdlPresentationInput presentationInput) {
    super(presentationInput.getNonce());
    this.clientId = presentationInput.getClientId();
    this.responseUri = presentationInput.getResponseUri();
    this.mdocGeneratedNonce = presentationInput.getMdocGeneratedNonce();
  }

  private String clientId;
  private String responseUri;
  private String mdocGeneratedNonce;
}

package se.digg.wallet.datatypes.mdl.data;

import lombok.Getter;
import se.digg.wallet.datatypes.common.PresentationInput;
import se.digg.wallet.datatypes.common.TokenSigningAlgorithm;

import java.util.List;
import java.util.Map;

@Getter
public class MdlPresentationInput extends PresentationInput<Map<String, List<String>>> {

  private String clientId;
  private String mdocGeneratedNonce;
  private String responseUri;

  public static MdlPresentationInputBuilder builder() {
    return new MdlPresentationInputBuilder();
  }

  public static class MdlPresentationInputBuilder {

    MdlPresentationInput mdlPresentationInput;

    public MdlPresentationInputBuilder() {
      mdlPresentationInput = new MdlPresentationInput();
    }

    public MdlPresentationInputBuilder token(byte[] token) {
      mdlPresentationInput.token = token;
      return this;
    }

    public MdlPresentationInputBuilder nonce(String nonce) {
      mdlPresentationInput.nonce = nonce;
      return this;
    }

    public MdlPresentationInputBuilder clientId(String walletId) {
      mdlPresentationInput.clientId = walletId;
      return this;
    }

    public MdlPresentationInputBuilder mdocGeneratedNonce(String mdocGeneratedNonce) {
      mdlPresentationInput.mdocGeneratedNonce = mdocGeneratedNonce;
      return this;
    }

    public MdlPresentationInputBuilder responseUri(String responseUri) {
      mdlPresentationInput.responseUri = responseUri;
      return this;
    }

    public MdlPresentationInputBuilder disclosures(Map<String, List<String>> disclosures) {
      mdlPresentationInput.disclosures = disclosures;
      return this;
    }

    public MdlPresentationInputBuilder algorithm(TokenSigningAlgorithm algorithm) {
      mdlPresentationInput.algorithm = algorithm;
      return this;
    }

    public MdlPresentationInput build() {
      return mdlPresentationInput;
    }
  }

}

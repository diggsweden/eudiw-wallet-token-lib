package se.digg.wallet.datatypes.mdl.data;

import com.upokecenter.cbor.CBORObject;
import lombok.Getter;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Objects;

/**
 * Provides a session transcript for use with OpenID4VP
 */
@Getter
public class SessionTranscript {

  private String clientId;
  private String responseUri;
  private String nonce;
  private String mdocGeneratedNonce;

  public SessionTranscript(String clientId, String responseUri, String nonce, String mdocGeneratedNonce) {
    this.clientId = clientId;
    this.responseUri = responseUri;
    this.nonce = nonce;
    this.mdocGeneratedNonce = mdocGeneratedNonce;
  }

  public CBORObject toCborObject() {
    Objects.requireNonNull(this.clientId, "clientId must not be null");
    Objects.requireNonNull(this.responseUri, "responseUri must not be null");
    Objects.requireNonNull(this.nonce, "nonce must not be null");
    Objects.requireNonNull(this.mdocGeneratedNonce, "mdocGeneratedNonce must not be null");

    CBORObject handover = CBORObject.NewArray();
    handover.Add(getHashItem(this.clientId, this.mdocGeneratedNonce));
    handover.Add(getHashItem(this.responseUri, this.mdocGeneratedNonce));
    handover.Add(CBORObject.FromObject(this.nonce));

    CBORObject sessionTranscript = CBORObject.NewArray();
    sessionTranscript.Add(null);
    sessionTranscript.Add(null);
    sessionTranscript.Add(handover);

    return sessionTranscript;
  }

  private CBORObject getHashItem(String clientId, String mdocGeneratedNonce) {
    try {
      MessageDigest messageDigest = MessageDigest.getInstance("SHA-256");
      CBORObject digestParamArray = CBORObject.NewArray();
      digestParamArray.Add(CBORObject.FromString(clientId));
      digestParamArray.Add(CBORObject.FromString(mdocGeneratedNonce));
      messageDigest.update(digestParamArray.EncodeToBytes());
      return CBORObject.FromByteArray(messageDigest.digest());
    } catch (NoSuchAlgorithmException e) {
      throw new RuntimeException(e);
    }
  }

}

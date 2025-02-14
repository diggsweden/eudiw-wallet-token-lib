// SPDX-FileCopyrightText: 2025 Digg - Agency for Digital Government
//
// SPDX-License-Identifier: EUPL-1.2

package se.digg.wallet.datatypes.mdl.data;

import com.upokecenter.cbor.CBORObject;
import com.upokecenter.numbers.EInteger;

/**
 * Device authentication payload for OpenID4VP
 */
public class DeviceAuthentication {

  private final String docType;
  private final SessionTranscript sessionTranscript;
  private final CBORObject nameSpaces;

  /**
   * Constructs a {@code DeviceAuthentication} object.
   *
   * @param docType A string representing the type of the document being authenticated.
   * @param sessionTranscript A {@code SessionTranscript} object containing the session transcript data used for authentication.
   */
  public DeviceAuthentication(
    String docType,
    SessionTranscript sessionTranscript
  ) {
    this.docType = docType;
    this.sessionTranscript = sessionTranscript;
    this.nameSpaces = CBORObject.NewMap();
  }

  /**
   * Constructs a {@code DeviceAuthentication} object.
   *
   * @param docType A string representing the type of the document being authenticated.
   * @param sessionTranscript A {@code SessionTranscript} object containing the session transcript data used for authentication.
   * @param nameSpaces A {@code CBORObject} representing the data namespaces involved in authentication.
   */
  public DeviceAuthentication(
    String docType,
    SessionTranscript sessionTranscript,
    CBORObject nameSpaces
  ) {
    this.docType = docType;
    this.sessionTranscript = sessionTranscript;
    this.nameSpaces = nameSpaces;
  }

  /**
   * Generates a CBOR-encoded byte array representing the device authentication payload.
   * The payload includes the following components:
   * - A string identifier ("DeviceAuthentication").
   * - The session transcript converted to CBOR format.
   * - The document type as a string.
   * - The namespaces as a tagged CBOR object.
   *
   * @return A CBOR-encoded byte array representation of the device authentication payload.
   */
  public byte[] getDeviceAuthenticationBytes() {
    CBORObject deviceAuthentication = CBORObject.NewArray();
    deviceAuthentication.Add(CBORObject.FromString("DeviceAuthentication"));
    deviceAuthentication.Add(this.sessionTranscript.toCborObject());
    deviceAuthentication.Add(CBORObject.FromString(this.docType));
    deviceAuthentication.Add(
      CBORObject.FromCBORObjectAndTag(
        CBORObject.FromByteArray(this.nameSpaces.EncodeToBytes()),
        EInteger.FromInt32(24)
      )
    );
    return CBORObject.FromCBORObjectAndTag(
      CBORObject.FromByteArray(deviceAuthentication.EncodeToBytes()),
      EInteger.FromInt32(24)
    ).EncodeToBytes();
  }
}

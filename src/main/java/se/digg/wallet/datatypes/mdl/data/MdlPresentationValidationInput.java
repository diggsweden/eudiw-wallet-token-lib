// SPDX-FileCopyrightText: 2025 Digg - Agency for Digital Government
//
// SPDX-License-Identifier: EUPL-1.2

package se.digg.wallet.datatypes.mdl.data;

import java.security.PrivateKey;
import lombok.Data;
import lombok.EqualsAndHashCode;
import lombok.NoArgsConstructor;
import se.digg.wallet.datatypes.common.PresentationValidationInput;

/**
 * MdlPresentationValidationInput is a specialized subclass of PresentationValidationInput,
 * designed to handle the validation input for mDL (mobile Driver's License) presentations.
 * It extends the functionality of the parent class by encapsulating additional fields
 * specific to mDL validation requirements, such as clientId, responseUri, and mdocGeneratedNonce.
 */
@EqualsAndHashCode(callSuper = true)
@Data
@NoArgsConstructor
public class MdlPresentationValidationInput
  extends PresentationValidationInput {

  /**
   * Constructs a new instance of {@code MdlPresentationValidationInput} by extracting relevant
   * fields from the provided {@code MdlPresentationInput} object. The constructor initializes
   * the parent class with the request nonce and sets the client ID, response URI, and mdoc
   * generated nonce specific to mDL presentations.
   *
   * @param presentationInput the {@code MdlPresentationInput} object containing the input data
   *                          required to initialize this instance, including the client ID,
   *                          response URI, and mdoc generated nonce
   */
  public MdlPresentationValidationInput(
    MdlPresentationInput presentationInput
  ) {
    super(presentationInput.getNonce());
    this.clientId = presentationInput.getClientId();
    this.responseUri = presentationInput.getResponseUri();
    this.mdocGeneratedNonce = presentationInput.getMdocGeneratedNonce();
  }

  /** The presentation requester client ID (OpenID4VP) */
  private String clientId;
  /** The return URL for the presentation response */
  private String responseUri;
  /** The wallet generated nonce included as the apu header parameter in the presentation response JWT */
  private String mdocGeneratedNonce;
  /** Optional private key for MAC validation */
  private PrivateKey clientPrivateKey;
}

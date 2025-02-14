// SPDX-FileCopyrightText: 2024 Digg - Agency for Digital Government
//
// SPDX-License-Identifier: EUPL-1.2

package se.digg.wallet.datatypes.mdl.process;

import lombok.Data;
import lombok.EqualsAndHashCode;
import lombok.NoArgsConstructor;
import se.digg.wallet.datatypes.common.TokenValidationResult;
import se.digg.wallet.datatypes.mdl.data.IssuerSigned;
import se.digg.wallet.datatypes.mdl.data.MobileSecurityObject;

/**
 * Represents the result of validation for an issuer-signed Mobile Driving License (mDL) token.
 * This class holds additional data specific to issuer-signed validation results, beyond the
 * general token validation data provided by the parent class {@code TokenValidationResult}.
 * <p>
 * The {@code MdlIssuerSignedValidationResult} class extends {@code TokenValidationResult}
 * by including data fields for the issuer-signed content and the Mobile Security Object (MSO).
 */
@EqualsAndHashCode(callSuper = true)
@Data
@NoArgsConstructor
public class MdlIssuerSignedValidationResult extends TokenValidationResult {

  /** Represents the token or data structure containing information signed by the issuer */
  protected IssuerSigned issuerSigned;
  /** Represents the Mobile Security Object, which encapsulates relevant signed data used in token validation */
  protected MobileSecurityObject mso;
}

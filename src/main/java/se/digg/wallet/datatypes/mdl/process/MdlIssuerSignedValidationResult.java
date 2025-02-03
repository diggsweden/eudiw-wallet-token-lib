// SPDX-FileCopyrightText: 2024 Digg - Agency for Digital Government
//
// SPDX-License-Identifier: EUPL-1.2

package se.digg.wallet.datatypes.mdl.process;

import lombok.*;
import se.digg.wallet.datatypes.common.TokenValidationResult;
import se.digg.wallet.datatypes.mdl.data.IssuerSigned;
import se.digg.wallet.datatypes.mdl.data.MobileSecurityObject;

@EqualsAndHashCode(callSuper = true)
@Data
@NoArgsConstructor
public class MdlIssuerSignedValidationResult extends TokenValidationResult {
  protected IssuerSigned issuerSigned;
  protected MobileSecurityObject mso;
}

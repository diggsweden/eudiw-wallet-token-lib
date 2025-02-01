// SPDX-FileCopyrightText: 2024 Digg - Agency for Digital Government
//
// SPDX-License-Identifier: EUPL-1.2

package se.digg.wallet.datatypes.mdl.process;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;
import se.digg.wallet.datatypes.common.TokenValidationResult;
import se.digg.wallet.datatypes.mdl.data.IssuerSigned;
import se.digg.wallet.datatypes.mdl.data.MobileSecurityObject;

@Data
@AllArgsConstructor
@NoArgsConstructor
public class MdlIssuerSignedValidationResult
  extends TokenValidationResult {

  protected IssuerSigned issuerSigned;
  protected MobileSecurityObject mso;

}

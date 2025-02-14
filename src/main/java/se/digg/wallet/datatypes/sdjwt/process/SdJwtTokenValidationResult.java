// SPDX-FileCopyrightText: 2024 Digg - Agency for Digital Government
//
// SPDX-License-Identifier: EUPL-1.2

package se.digg.wallet.datatypes.sdjwt.process;

import com.nimbusds.jose.Payload;
import java.util.List;
import lombok.Data;
import lombok.EqualsAndHashCode;
import lombok.NoArgsConstructor;
import se.digg.wallet.datatypes.common.TokenValidationResult;
import se.digg.wallet.datatypes.sdjwt.data.SdJwt;

/**
 * Extended validation results for SdJwt validation
 */
@EqualsAndHashCode(callSuper = true)
@Data
@NoArgsConstructor
public class SdJwtTokenValidationResult extends TokenValidationResult {

  private SdJwt vcToken;
  private Payload disclosedTokenPayload;
  private boolean keyBindingProtection;
  private List<String> audience;
}

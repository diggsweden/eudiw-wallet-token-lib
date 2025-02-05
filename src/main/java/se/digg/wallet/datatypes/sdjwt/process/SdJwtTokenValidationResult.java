// SPDX-FileCopyrightText: 2024 Digg - Agency for Digital Government
//
// SPDX-License-Identifier: EUPL-1.2

package se.digg.wallet.datatypes.sdjwt.process;

import com.nimbusds.jose.Payload;
import lombok.*;
import se.digg.wallet.datatypes.common.TokenValidationResult;
import se.digg.wallet.datatypes.sdjwt.data.SdJwt;

import java.util.List;

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

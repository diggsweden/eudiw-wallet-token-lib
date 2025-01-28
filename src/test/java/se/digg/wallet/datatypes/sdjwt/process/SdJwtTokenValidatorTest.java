// SPDX-FileCopyrightText: 2024 Digg - Agency for Digital Government
//
// SPDX-License-Identifier: EUPL-1.2

package se.digg.wallet.datatypes.sdjwt.process;

import static org.junit.jupiter.api.Assertions.*;

import java.nio.charset.StandardCharsets;
import org.junit.jupiter.api.Test;
import se.digg.wallet.datatypes.common.TokenValidationResult;
import se.digg.wallet.datatypes.common.TokenValidator;
import se.digg.wallet.datatypes.mdl.data.TestData;

class SdJwtTokenValidatorTest {

  @Test
  void refValidationTest() throws Exception {
    SdJwtTokenValidator tokenValidator = new SdJwtTokenValidator();
    //SdJwtTokenValidationResult result = tokenValidator.validateToken(wTestData.SD_TWT_RFC_REF.getBytes(StandardCharsets.UTF_8), null);
    int sdf = 0;
  }
}

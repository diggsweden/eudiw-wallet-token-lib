package se.digg.wallet.datatypes.sdjwt.process;

import org.junit.jupiter.api.Test;
import se.digg.wallet.datatypes.common.TokenValidationResult;
import se.digg.wallet.datatypes.common.TokenValidator;
import se.digg.wallet.datatypes.mdl.data.TestData;

import java.nio.charset.StandardCharsets;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Description
 */
class SdJwtTokenValidatorTest {

  @Test
  void refValidationTest() throws Exception{

    SdJwtTokenValidator tokenValidator = new SdJwtTokenValidator();
    //SdJwtTokenValidationResult result = tokenValidator.validateToken(wTestData.SD_TWT_RFC_REF.getBytes(StandardCharsets.UTF_8), null);
    int sdf = 0;
  }
}
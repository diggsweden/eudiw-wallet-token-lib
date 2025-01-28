// SPDX-FileCopyrightText: 2024 Digg - Agency for Digital Government
//
// SPDX-License-Identifier: EUPL-1.2

package se.digg.wallet.datatypes.mdl.data;

import static org.junit.jupiter.api.Assertions.*;

import java.time.Duration;
import java.time.Instant;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import lombok.extern.slf4j.Slf4j;
import org.bouncycastle.util.encoders.Hex;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import se.idsec.cose.AlgorithmID;
import se.idsec.cose.COSEKey;

@Slf4j
class MobileSecurityObjectTest {

  @Test
  void testSerialize() throws Exception {
    Map<String, Map<Integer, byte[]>> valueDigests = new HashMap<>();
    Map<Integer, byte[]> digestValues = new HashMap<>();
    digestValues.put(
      1,
      Hex.decode(
        "ab92f0509e09cbc333066011eceeb95bfe0d8b14a5dca9269f5a6c9aea1c0997"
      )
    );
    digestValues.put(
      2,
      Hex.decode(
        "bbb0fedefafe36b2e0df38a0ba753310a16a600c86e6c03e7dfbe60e3471676e"
      )
    );
    digestValues.put(
      3,
      Hex.decode(
        "b63819e1a19161a84eecf0f45f75e8fcb797eba7e1e017fd97e2a32dcef118e8"
      )
    );
    digestValues.put(
      4,
      Hex.decode(
        "117fae5f77551db5ba69087523225aa1664f9271b349f71f9496a275ab2680eb"
      )
    );
    digestValues.put(
      5,
      Hex.decode(
        "283bd5c8c537e7c2ded27e939156f673405b85b48c270a6cc2d3cb36266b4d1f"
      )
    );
    digestValues.put(
      6,
      Hex.decode(
        "056732700269c2ed070c430abbd850d09663f1934e37e1c65b87afebb7555a81"
      )
    );
    digestValues.put(
      7,
      Hex.decode(
        "7c011d0dfeb153ed728f9171486e618aba8a2bee8e36322664016d0fce761143"
      )
    );
    valueDigests.put("org.iso.18013.5.1", digestValues);

    MobileSecurityObject mso = MobileSecurityObject.builder()
      .version("1.0")
      .digestAlgorithm("SHA-256")
      .valueDigests(valueDigests)
      .docType("org.iso.18013.5.1.mDL")
      .validityInfo(
        MobileSecurityObject.ValidityInfo.builder()
          .signed(Instant.now())
          .validFrom(Instant.now())
          .validUntil(Instant.now().plus(Duration.ofDays(2)))
          .build()
      )
      .deviceKeyInfo(
        MobileSecurityObject.DeviceKeyInfo.builder()
          .deviceKey(COSEKey.generateKey(AlgorithmID.ECDSA_256))
          .keyAuthorizations(
            MobileSecurityObject.KeyAuthorizations.builder()
              .nameSpaces(List.of("org.iso.18013.5.1"))
              .build()
          )
          .build()
      )
      .build();

    byte[] msoBytes = CBORUtils.CBOR_MAPPER.writeValueAsBytes(mso);
    log.info("MSO CBOR:\n{}", Hex.toHexString(msoBytes));

    byte[] coseSigned = mso
      .sign(
        null,
        COSEKey.generateKey(AlgorithmID.ECDSA_256),
        AlgorithmID.ECDSA_256
      )
      .EncodeToBytes();
    log.info("COSE Signed:\n{}", Hex.toHexString(coseSigned));

    MobileSecurityObject deserializedMobileSecurityObject =
      MobileSecurityObject.deserialize(msoBytes);
    // TODO compare internal objects of mso and deserialized mso
  }
}

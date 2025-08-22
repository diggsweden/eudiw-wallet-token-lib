// SPDX-FileCopyrightText: 2025 diggsweden/eudiw-wallet-token-lib
//
// SPDX-License-Identifier: EUPL-1.2

package se.digg.wallet.datatypes.mdl.data;

import lombok.extern.slf4j.Slf4j;
import org.bouncycastle.util.encoders.Hex;
import org.junit.jupiter.api.Test;

@Slf4j
class DeviceAuthenticationTest {

  @Test
  void deviceAuthenticationTest() {
    DeviceAuthentication deviceAuthentication = new DeviceAuthentication(
        "org.iso.18013.5.1.mDL",
        new SessionTranscript(
            "https://example.com/client",
            "https://example.com/response",
            "abcdefgh1234567890",
            "MTIzNDU2Nzg5MGFiY2RlZmdo"));

    byte[] deviceAuthenticationBytes = deviceAuthentication.getDeviceAuthenticationBytes();
    log.info(
        "DeviceAuthenticationBytes:\n{}",
        Hex.toHexString(deviceAuthenticationBytes));
  }
}

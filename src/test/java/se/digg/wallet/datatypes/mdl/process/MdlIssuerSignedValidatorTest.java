// SPDX-FileCopyrightText: 2024 diggsweden/eudiw-wallet-token-lib
//
// SPDX-License-Identifier: EUPL-1.2

package se.digg.wallet.datatypes.mdl.process;

import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.fail;

import com.upokecenter.cbor.CBORObject;
import java.security.PublicKey;
import java.time.Duration;
import java.time.Instant;
import java.util.Base64;
import java.util.List;
import lombok.extern.slf4j.Slf4j;
import org.bouncycastle.util.encoders.Hex;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import se.digg.wallet.datatypes.common.TestCredentials;
import se.digg.wallet.datatypes.common.TestData;
import se.digg.wallet.datatypes.common.TokenInput;
import se.digg.wallet.datatypes.common.TokenSigningAlgorithm;
import se.digg.wallet.datatypes.common.TokenValidationException;
import se.digg.wallet.datatypes.common.TrustedKey;
import se.swedenconnect.security.credential.PkiCredential;

/**
 * Test of the mDL Issuer Signed Validator
 */
@Slf4j
class MdlIssuerSignedValidatorTest {

  static MdlTokenIssuer tokenIssuer;

  @BeforeAll
  static void setup() {
    tokenIssuer = new MdlTokenIssuer();
  }

  @Test
  void testReferenceImplPIDExampleExpired() throws Exception {
    byte[] issuerSignedBytes = Base64.getUrlDecoder()
        .decode(
            "omppc3N1ZXJBdXRohEOhASahGCFZAukwggLlMIICaqADAgECAhRoQu0mnaibjqEFrDO7g1RxBIyzBDAKBggqhkjOPQQDAjBcMR4wHAYDVQQDDBVQSUQgSXNzdWVyIENBIC0gVVQgMDExLTArBgNVBAoMJEVVREkgV2FsbGV0IFJlZmVyZW5jZSBJbXBsZW1lbnRhdGlvbjELMAkGA1UEBhMCVVQwHhcNMjQwNzAxMTAwMzA2WhcNMjUwOTI0MTAwMzA1WjBUMRYwFAYDVQQDDA1QSUQgRFMgLSAwMDAyMS0wKwYDVQQKDCRFVURJIFdhbGxldCBSZWZlcmVuY2UgSW1wbGVtZW50YXRpb24xCzAJBgNVBAYTAlVUMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE66T6UUJ8d2wrkB_g0zroSJ_boX3LL1wToHmFgFCaVQoS5OQ6gx64rPFJ36iBrfXBZbWUOvORiayYAE6H1XXyVKOCARAwggEMMB8GA1UdIwQYMBaAFLNsuJEXHNekGmYxh0Lhi8BAzJUbMBYGA1UdJQEB_wQMMAoGCCuBAgIAAAECMEMGA1UdHwQ8MDowOKA2oDSGMmh0dHBzOi8vcHJlcHJvZC5wa2kuZXVkaXcuZGV2L2NybC9waWRfQ0FfVVRfMDEuY3JsMB0GA1UdDgQWBBQEfQ5D1-0ZE9VvaFJOS-fzBhMSyjAOBgNVHQ8BAf8EBAMCB4AwXQYDVR0SBFYwVIZSaHR0cHM6Ly9naXRodWIuY29tL2V1LWRpZ2l0YWwtaWRlbnRpdHktd2FsbGV0L2FyY2hpdGVjdHVyZS1hbmQtcmVmZXJlbmNlLWZyYW1ld29yazAKBggqhkjOPQQDAgNpADBmAjEAkfm_P8cc8y1BtYvC4tH1-iB1spuGpMRpYvxZZxpbhoMZ10fyDDwXC-knmtzkP0p7AjEA2l-9N2LXnG-vqaO2rCgylMXMV8L_HHB-fW_WThZoljQc5_XuOihslQXdIyY-BTvbWQJZ2BhZAlSmZ2RvY1R5cGV3ZXUuZXVyb3BhLmVjLmV1ZGkucGlkLjFndmVyc2lvbmMxLjBsdmFsaWRpdHlJbmZvo2ZzaWduZWTAdDIwMjQtMTEtMTlUMDc6NDk6MjJaaXZhbGlkRnJvbcB0MjAyNC0xMS0xOVQwNzo0OToyMlpqdmFsaWRVbnRpbMB0MjAyNS0wMi0xN1QwMDowMDowMFpsdmFsdWVEaWdlc3RzoXdldS5ldXJvcGEuZWMuZXVkaS5waWQuMagAWCCGNciAN9igIeefh-AQ24CTD1s5ORel1XP6hPVz3K3QmQFYINawr_Kdw9G05xrGf1TFQD85TNYkdT60thyE9MrcSoBNAlggBq91GsYxZmah6lMMfvL9CizLxzuw1uAgwDtRIk42pJ4DWCBtTtVrgul7w-q4MZQ0hEMADThV8av9NB3qWvYnsUA8JwRYIK3lQYLuc_Kqz0Tdwh1AYG3GIGEVx3LGmbYsdHBjNP7wBVggGOM7qlE0zCuypNJlRA7kji-bajVG0AjFyb9hH8W8hNsGWCBVss1tDxnZKwHgGstmqCOXquTRUc0mFGIlXPMOS_o07wdYIAju4pNtAereVAFZs5P73nx0gLd7gDEnCrINUFfPFvIUbWRldmljZUtleUluZm-haWRldmljZUtleaQBAiABIVggGrIEwKcz8CGMXiHuLu9_lhhjS3o7CpFMAQig0fsjVAgiWCDtwkQGOvgl5Qwbrf8iHmhkFE_8Xg0OrYUwCNh5jgzaAm9kaWdlc3RBbGdvcml0aG1nU0hBLTI1NlhAq7N4-Y7IRpOmwhoUix4mNNXKwAzyOAPnRsqXofpjWWEGvGoFI8n3u35SoRYRDFHBBhYOH_INJG5tswXXMeKnjmpuYW1lU3BhY2VzoXdldS5ldXJvcGEuZWMuZXVkaS5waWQuMYjYGFhvpGZyYW5kb21YIGVoS8sXJh-ZQ_LQATusxoxaTHZ4Rwdcpd9KWWSu_ULqaGRpZ2VzdElEAGxlbGVtZW50VmFsdWXZA-xqMjAyNC0xMS0xOXFlbGVtZW50SWRlbnRpZmllcm1pc3N1YW5jZV9kYXRl2BhYZqRmcmFuZG9tWCDdaC8sDcj0xRude-HNRYyYSk4DfYcZkqOT_f93BTQPWWhkaWdlc3RJRAFsZWxlbWVudFZhbHVlYkZDcWVsZW1lbnRJZGVudGlmaWVyb2lzc3VpbmdfY291bnRyedgYWGWkZnJhbmRvbVgg2P2y7jnQZSixYYHTEc23U34Hv16jjF98VE_KTdnd1K5oZGlnZXN0SUQCbGVsZW1lbnRWYWx1ZWZKb2hubnlxZWxlbWVudElkZW50aWZpZXJqZ2l2ZW5fbmFtZdgYWGCkZnJhbmRvbVgge5HlU0GvXGjGRtFznX_gBDoDNN221Usojn5f30IZiztoZGlnZXN0SUQDbGVsZW1lbnRWYWx1ZfVxZWxlbWVudElkZW50aWZpZXJrYWdlX292ZXJfMTjYGFhspGZyYW5kb21YIBkLoFfpzjJsL3c92pTNT78-AabhwNJnRl4VO6VGKjfCaGRpZ2VzdElEBGxlbGVtZW50VmFsdWXZA-xqMTk4Ni0wMi0yMXFlbGVtZW50SWRlbnRpZmllcmpiaXJ0aF9kYXRl2BhYbaRmcmFuZG9tWCBwu_EZgKggzK40rVlY84u4yF2fT9ZO_4gdUa5tZuCInWhkaWdlc3RJRAVsZWxlbWVudFZhbHVl2QPsajIwMjUtMDItMTdxZWxlbWVudElkZW50aWZpZXJrZXhwaXJ5X2RhdGXYGFhnpGZyYW5kb21YIBRpZIUVP1qZhWZ54HoFOIGhiAAXXDTveL2sUoz_IDKwaGRpZ2VzdElEBmxlbGVtZW50VmFsdWVnVGh1bGFuZHFlbGVtZW50SWRlbnRpZmllcmtmYW1pbHlfbmFtZdgYWHWkZnJhbmRvbVggznvLq6zlDkRQIKVzyWWzGdcWxgCa3Xl8mlrXBHwEFYNoZGlnZXN0SUQHbGVsZW1lbnRWYWx1ZW9UZXN0IFBJRCBpc3N1ZXJxZWxlbWVudElkZW50aWZpZXJxaXNzdWluZ19hdXRob3JpdHk=");
    MdlIssuerSignedValidator validator = new MdlIssuerSignedValidator();

    try {
      validator.validateToken(
          issuerSignedBytes,
          null);
    } catch (TokenValidationException e) {
      log.info(
          "Expired token throw error on validation suceeded. token:\n{}",
          Hex.toHexString(issuerSignedBytes));
      return;
    }
    throw new Exception("Expired token should not validate");
  }

  @Test
  void testReferenceImplPIDExample() throws Exception {
    byte[] issuerSignedBytes = Base64.getUrlDecoder()
        .decode(
            "omppc3N1ZXJBdXRohEOhASahGCFZAukwggLlMIICaqADAgECAhRoQu0mnaibjqEFrDO7g1RxBIyzBDAKBggqhkjOPQQDAjBcMR4wHAYDVQQDDBVQSUQgSXNzdWVyIENBIC0gVVQgMDExLTArBgNVBAoMJEVVREkgV2FsbGV0IFJlZmVyZW5jZSBJbXBsZW1lbnRhdGlvbjELMAkGA1UEBhMCVVQwHhcNMjQwNzAxMTAwMzA2WhcNMjUwOTI0MTAwMzA1WjBUMRYwFAYDVQQDDA1QSUQgRFMgLSAwMDAyMS0wKwYDVQQKDCRFVURJIFdhbGxldCBSZWZlcmVuY2UgSW1wbGVtZW50YXRpb24xCzAJBgNVBAYTAlVUMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE66T6UUJ8d2wrkB_g0zroSJ_boX3LL1wToHmFgFCaVQoS5OQ6gx64rPFJ36iBrfXBZbWUOvORiayYAE6H1XXyVKOCARAwggEMMB8GA1UdIwQYMBaAFLNsuJEXHNekGmYxh0Lhi8BAzJUbMBYGA1UdJQEB_wQMMAoGCCuBAgIAAAECMEMGA1UdHwQ8MDowOKA2oDSGMmh0dHBzOi8vcHJlcHJvZC5wa2kuZXVkaXcuZGV2L2NybC9waWRfQ0FfVVRfMDEuY3JsMB0GA1UdDgQWBBQEfQ5D1-0ZE9VvaFJOS-fzBhMSyjAOBgNVHQ8BAf8EBAMCB4AwXQYDVR0SBFYwVIZSaHR0cHM6Ly9naXRodWIuY29tL2V1LWRpZ2l0YWwtaWRlbnRpdHktd2FsbGV0L2FyY2hpdGVjdHVyZS1hbmQtcmVmZXJlbmNlLWZyYW1ld29yazAKBggqhkjOPQQDAgNpADBmAjEAkfm_P8cc8y1BtYvC4tH1-iB1spuGpMRpYvxZZxpbhoMZ10fyDDwXC-knmtzkP0p7AjEA2l-9N2LXnG-vqaO2rCgylMXMV8L_HHB-fW_WThZoljQc5_XuOihslQXdIyY-BTvbWQJZ2BhZAlSmZ2RvY1R5cGV3ZXUuZXVyb3BhLmVjLmV1ZGkucGlkLjFndmVyc2lvbmMxLjBsdmFsaWRpdHlJbmZvo2ZzaWduZWTAdDIwMjQtMTEtMTlUMDc6NDk6MjJaaXZhbGlkRnJvbcB0MjAyNC0xMS0xOVQwNzo0OToyMlpqdmFsaWRVbnRpbMB0MjAyNS0wMi0xN1QwMDowMDowMFpsdmFsdWVEaWdlc3RzoXdldS5ldXJvcGEuZWMuZXVkaS5waWQuMagAWCCGNciAN9igIeefh-AQ24CTD1s5ORel1XP6hPVz3K3QmQFYINawr_Kdw9G05xrGf1TFQD85TNYkdT60thyE9MrcSoBNAlggBq91GsYxZmah6lMMfvL9CizLxzuw1uAgwDtRIk42pJ4DWCBtTtVrgul7w-q4MZQ0hEMADThV8av9NB3qWvYnsUA8JwRYIK3lQYLuc_Kqz0Tdwh1AYG3GIGEVx3LGmbYsdHBjNP7wBVggGOM7qlE0zCuypNJlRA7kji-bajVG0AjFyb9hH8W8hNsGWCBVss1tDxnZKwHgGstmqCOXquTRUc0mFGIlXPMOS_o07wdYIAju4pNtAereVAFZs5P73nx0gLd7gDEnCrINUFfPFvIUbWRldmljZUtleUluZm-haWRldmljZUtleaQBAiABIVggGrIEwKcz8CGMXiHuLu9_lhhjS3o7CpFMAQig0fsjVAgiWCDtwkQGOvgl5Qwbrf8iHmhkFE_8Xg0OrYUwCNh5jgzaAm9kaWdlc3RBbGdvcml0aG1nU0hBLTI1NlhAq7N4-Y7IRpOmwhoUix4mNNXKwAzyOAPnRsqXofpjWWEGvGoFI8n3u35SoRYRDFHBBhYOH_INJG5tswXXMeKnjmpuYW1lU3BhY2VzoXdldS5ldXJvcGEuZWMuZXVkaS5waWQuMYjYGFhvpGZyYW5kb21YIGVoS8sXJh-ZQ_LQATusxoxaTHZ4Rwdcpd9KWWSu_ULqaGRpZ2VzdElEAGxlbGVtZW50VmFsdWXZA-xqMjAyNC0xMS0xOXFlbGVtZW50SWRlbnRpZmllcm1pc3N1YW5jZV9kYXRl2BhYZqRmcmFuZG9tWCDdaC8sDcj0xRude-HNRYyYSk4DfYcZkqOT_f93BTQPWWhkaWdlc3RJRAFsZWxlbWVudFZhbHVlYkZDcWVsZW1lbnRJZGVudGlmaWVyb2lzc3VpbmdfY291bnRyedgYWGWkZnJhbmRvbVgg2P2y7jnQZSixYYHTEc23U34Hv16jjF98VE_KTdnd1K5oZGlnZXN0SUQCbGVsZW1lbnRWYWx1ZWZKb2hubnlxZWxlbWVudElkZW50aWZpZXJqZ2l2ZW5fbmFtZdgYWGCkZnJhbmRvbVgge5HlU0GvXGjGRtFznX_gBDoDNN221Usojn5f30IZiztoZGlnZXN0SUQDbGVsZW1lbnRWYWx1ZfVxZWxlbWVudElkZW50aWZpZXJrYWdlX292ZXJfMTjYGFhspGZyYW5kb21YIBkLoFfpzjJsL3c92pTNT78-AabhwNJnRl4VO6VGKjfCaGRpZ2VzdElEBGxlbGVtZW50VmFsdWXZA-xqMTk4Ni0wMi0yMXFlbGVtZW50SWRlbnRpZmllcmpiaXJ0aF9kYXRl2BhYbaRmcmFuZG9tWCBwu_EZgKggzK40rVlY84u4yF2fT9ZO_4gdUa5tZuCInWhkaWdlc3RJRAVsZWxlbWVudFZhbHVl2QPsajIwMjUtMDItMTdxZWxlbWVudElkZW50aWZpZXJrZXhwaXJ5X2RhdGXYGFhnpGZyYW5kb21YIBRpZIUVP1qZhWZ54HoFOIGhiAAXXDTveL2sUoz_IDKwaGRpZ2VzdElEBmxlbGVtZW50VmFsdWVnVGh1bGFuZHFlbGVtZW50SWRlbnRpZmllcmtmYW1pbHlfbmFtZdgYWHWkZnJhbmRvbVggznvLq6zlDkRQIKVzyWWzGdcWxgCa3Xl8mlrXBHwEFYNoZGlnZXN0SUQHbGVsZW1lbnRWYWx1ZW9UZXN0IFBJRCBpc3N1ZXJxZWxlbWVudElkZW50aWZpZXJxaXNzdWluZ19hdXRob3JpdHk=");
    MdlIssuerSignedValidator validator = new MdlIssuerSignedValidator(Duration.ofDays(365 * 100));
    MdlIssuerSignedValidationResult validationResult = validator.validateToken(
        issuerSignedBytes,
        null);

    log.info(
        "Validation suceeded of token:\n{}",
        Hex.toHexString(issuerSignedBytes));
    log.info(
        "Signing certificate:\n{}",
        validationResult.getValidationCertificate().toString());
  }

  /**
   * Test to be deleted later. This test is kind of pointless, as fixing the problem with tagged
   * payload does not fix the signature error.
   */
  @Test
  void testMdlExample() {
    byte[] mdlExampleMdoc = Base64.getUrlDecoder()
        .decode(
            "omdkb2NUeXBldW9yZy5pc28uMTgwMTMuNS4xLm1ETGxpc3N1ZXJTaWduZWSiam5hbWVTcGFjZXOhcW9yZy5pc28uMTgwMTMuNS4xiNgYWFukaGRpZ2VzdElEAWZyYW5kb21QcbnmTIHt0_17t-AcHkKZbHFlbGVtZW50SWRlbnRpZmllcmppc3N1ZV9kYXRlbGVsZW1lbnRWYWx1ZdkD7GoyMDI0LTAxLTEy2BhYXKRoZGlnZXN0SUQCZnJhbmRvbVBRwvzBVJYBc2plhd7vXZwTcWVsZW1lbnRJZGVudGlmaWVya2V4cGlyeV9kYXRlbGVsZW1lbnRWYWx1ZdkD7GoyMDI1LTAxLTEy2BhYWqRoZGlnZXN0SUQDZnJhbmRvbVDcuBh2xE6SqxDDECOY9H3CcWVsZW1lbnRJZGVudGlmaWVya2ZhbWlseV9uYW1lbGVsZW1lbnRWYWx1ZWtTaWx2ZXJzdG9uZdgYWFKkaGRpZ2VzdElEBGZyYW5kb21QHu5Fe96gJQH-NeOAvSuJdHFlbGVtZW50SWRlbnRpZmllcmpnaXZlbl9uYW1lbGVsZW1lbnRWYWx1ZWRJbmdh2BhYW6RoZGlnZXN0SUQFZnJhbmRvbVDI-4b03R-29ljFhUoZMHP0cWVsZW1lbnRJZGVudGlmaWVyamJpcnRoX2RhdGVsZWxlbWVudFZhbHVl2QPsajE5OTEtMTEtMDbYGFhVpGhkaWdlc3RJRAZmcmFuZG9tUCJlXpl0UAxhiiN9BwSnLeBxZWxlbWVudElkZW50aWZpZXJvaXNzdWluZ19jb3VudHJ5bGVsZW1lbnRWYWx1ZWJVU9gYWFukaGRpZ2VzdElEB2ZyYW5kb21QbWz_ggUxytSax7_FqCzoEHFlbGVtZW50SWRlbnRpZmllcm9kb2N1bWVudF9udW1iZXJsZWxlbWVudFZhbHVlaDEyMzQ1Njc42BhYoqRoZGlnZXN0SUQIZnJhbmRvbVBbSwOg91lMspu_ctBa2uqgcWVsZW1lbnRJZGVudGlmaWVycmRyaXZpbmdfcHJpdmlsZWdlc2xlbGVtZW50VmFsdWWBo3V2ZWhpY2xlX2NhdGVnb3J5X2NvZGVhQWppc3N1ZV9kYXRl2QPsajIwMjMtMDEtMDFrZXhwaXJ5X2RhdGXZA-xqMjA0My0wMS0wMWppc3N1ZXJBdXRohEOhASahGCFZAWEwggFdMIIBBKADAgECAgYBjJHZwhkwCgYIKoZIzj0EAwIwNjE0MDIGA1UEAwwrSjFGd0pQODdDNi1RTl9XU0lPbUpBUWM2bjVDUV9iWmRhRko1R0RuVzFSazAeFw0yMzEyMjIxNDA2NTZaFw0yNDEwMTcxNDA2NTZaMDYxNDAyBgNVBAMMK0oxRndKUDg3QzYtUU5fV1NJT21KQVFjNm41Q1FfYlpkYUZKNUdEblcxUmswWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAAQCilV5ugmlhHJzDVgqSRE5d8KkoQqX1jVg8WE4aPjFODZQ66fFPFIhWRP3ioVUi67WGQSgTY3F6Vmjf7JMVQ4MMAoGCCqGSM49BAMCA0cAMEQCIGcWNJwFy8RGV4uMwK7k1vEkqQ2xr-BCGRdN8OZur5PeAiBVrNuxV1C9mCW5z2clhDFaXNdP2Lp_7CBQrHQoJhuPcNgYWQHopWd2ZXJzaW9uYzEuMG9kaWdlc3RBbGdvcml0aG1nU0hBLTI1Nmx2YWx1ZURpZ2VzdHOhcW9yZy5pc28uMTgwMTMuNS4xqAFYIKuS8FCeCcvDMwZgEezuuVv-DYsUpdypJp9abJrqHAmXAlggu7D-3vr-NrLg3zigunUzEKFqYAyG5sA-ffvmDjRxZ24DWCC2OBnhoZFhqE7s8PRfdej8t5frp-HgF_2X4qMtzvEY6ARYIBF_rl93VR21umkIdSMiWqFmT5Jxs0n3H5SWonWrJoDrBVggKDvVyMU358Le0n6TkVb2c0BbhbSMJwpswtPLNiZrTR8GWCAFZzJwAmnC7QcMQwq72FDQlmPxk0434cZbh6_rt1VagQdYIHwBHQ3-sVPtco-RcUhuYYq6iivujjYyJmQBbQ_OdhFDCFggcjT2HYgkoxnwWP-9jqO_6-D-d69H9UW2xjpDWrknlvBnZG9jVHlwZXVvcmcuaXNvLjE4MDEzLjUuMS5tRExsdmFsaWRpdHlJbmZvo2ZzaWduZWTAdDIwMjQtMDEtMTJUMDA6MTA6MDVaaXZhbGlkRnJvbcB0MjAyNC0wMS0xMlQwMDoxMDowNVpqdmFsaWRVbnRpbMB0MjAyNS0wMS0xMlQwMDoxMDowNVpYQHFzEb09NFyFlj533FE_1B9I2rku90K52ar64Id1CyOUXWXzhINeVfoJU1cfxgCT2CX1369cGd_TQxSjhVx8bpY");
    CBORObject mdocObject = CBORObject.DecodeFromBytes(mdlExampleMdoc);
    byte[] issuerSignedBytes = mdocObject.get("issuerSigned").EncodeToBytes();
    MdlIssuerSignedValidator validator = new MdlIssuerSignedValidator();
    TokenValidationException tokenValidationException = assertThrows(
        TokenValidationException.class,
        () -> {
          validator.validateToken(issuerSignedBytes, null);
        });
    // This validation fails because the COSE signature payload is not provided as
    // bstring data, but
    // instead as CBOR tagged data.
    // And that signature validation fails no matter what input we use.
    Assertions.assertEquals(
        "Token signature validation failed",
        tokenValidationException.getMessage());
    log.info(
        "Got expected validation error: {}",
        tokenValidationException.toString());
  }

  // Test cases

  @Test
  void testCases() throws Exception {
    MdlIssuerSignedValidator defaultValidator = new MdlIssuerSignedValidator();
    byte[] ecToken = getToken(
        tokenIssuer,
        TestCredentials.p256_issuerCredential,
        TestCredentials.p256_walletKey.toPublicKey());
    byte[] rsaToken = getToken(
        tokenIssuer,
        TestCredentials.rsa_issuerCredential,
        TestCredentials.p256_walletKey.toPublicKey());
    List<TrustedKey> allTrusted = List.of(
        TrustedKey.builder()
            .certificate(TestCredentials.p256_issuerCredential.getCertificate())
            .build(),
        TrustedKey.builder()
            .certificate(TestCredentials.rsa_issuerCredential.getCertificate())
            .build());
    List<TrustedKey> rsaTrusted = List.of(
        TrustedKey.builder()
            .certificate(TestCredentials.rsa_issuerCredential.getCertificate())
            .build());

    // Default test case
    assertTrue(
        performTestCase(
            "Default test case",
            defaultValidator,
            ecToken,
            allTrusted,
            null)
            .getValidationCertificate()
            .equals(TestCredentials.p256_issuerCredential.getCertificate()));
    assertTrue(
        performTestCase("No trusted keys", defaultValidator, ecToken, null, null)
            .getValidationCertificate()
            .equals(TestCredentials.p256_issuerCredential.getCertificate()));
    assertTrue(
        performTestCase(
            "RSA test case",
            defaultValidator,
            rsaToken,
            allTrusted,
            null)
            .getValidationCertificate()
            .equals(TestCredentials.rsa_issuerCredential.getCertificate()));
    performTestCase(
        "Untrusted key",
        defaultValidator,
        ecToken,
        rsaTrusted,
        TokenValidationException.class);
  }

  public static byte[] getToken(
      MdlTokenIssuer tokenIssuer,
      PkiCredential issuerCredential,
      PublicKey walletPublic) throws Exception {
    TokenSigningAlgorithm algorithm = issuerCredential
        .getPublicKey() instanceof java.security.interfaces.ECPublicKey
            ? TokenSigningAlgorithm.ECDSA_256
            : TokenSigningAlgorithm.RSA_PSS_256;

    return tokenIssuer.issueToken(
        TokenInput.builder()
            .algorithm(algorithm)
            .issuer("http://example.com/issuer")
            .issuerCredential(issuerCredential)
            .walletPublicKey(walletPublic)
            .expirationDuration(Duration.ofDays(1))
            .attributes(TestData.defaultPidUserAttributes)
            .build());
  }

  MdlIssuerSignedValidationResult performTestCase(
      String description,
      MdlIssuerSignedValidator validator,
      byte[] token,
      List<TrustedKey> trustedKeys,
      Class<? extends Exception> expectedException) throws Exception {
    log.info("TEST CASE:\n================\n{}\n================", description);

    if (expectedException != null) {
      Exception exception = assertThrows(expectedException, () -> {
        validator.validateToken(token, trustedKeys);
        fail("Expected exception not thrown");
      });
      log.info(
          "Thrown expected exception: {} - {}",
          exception.getClass().getSimpleName(),
          exception.getMessage());
      if (exception.getCause() != null) {
        log.info(
            "Cause: {} - {}",
            exception.getCause().getClass().getSimpleName(),
            exception.getCause().toString());
      }
    } else {
      MdlIssuerSignedValidationResult validationResult =
          validator.validateToken(token, trustedKeys);
      logValidationResult(validationResult);
      assertNotNull(validationResult);
      assertNotNull(validationResult.getValidationCertificate());
      assertNotNull(validationResult.getValidationKey());
      assertNotNull(validationResult.getMso());
      assertNotNull(validationResult.getIssuerSigned());
      assertTrue(validationResult.getIssueTime().isBefore(Instant.now()));
      assertTrue(
          validationResult
              .getExpirationTime()
              .isAfter(validationResult.getIssueTime()));
      assertTrue(validationResult.getExpirationTime().isAfter(Instant.now()));
      return validationResult;
    }
    return null;
  }

  public static void logValidationResult(
      MdlIssuerSignedValidationResult validationResult) {
    log.info("mDL validation successful");
    log.info(
        "Validation Certificate: {}",
        validationResult.getValidationCertificate().getSubjectX500Principal());
    log.info("Validation Key: {}", validationResult.getValidationKey());
    log.info("Issue Time: {}", validationResult.getIssueTime());
    log.info("Expiration Time: {}", validationResult.getExpirationTime());
    log.info(
        "Request nonce: {}",
        validationResult.getPresentationRequestNonce());
  }
}

package se.digg.wallet.datatypes.sdjwt;

import com.fasterxml.jackson.core.Base64Variant;
import lombok.extern.slf4j.Slf4j;
import org.junit.jupiter.api.Test;
import se.digg.wallet.datatypes.sdjwt.data.Disclosure;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.Base64;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Description
 */
@Slf4j
class JSONUtilsTest {

  @Test
  void testDisclosureHash() throws Exception {

    Disclosure disclosure = new Disclosure("WyIyR0xDNDJzS1F2ZUNmR2ZyeU5STjl3IiwgImdpdmVuX25hbWUiLCAiSm9obiJd");
    byte[] disclosureHash = JSONUtils.disclosureHash(disclosure, "SHA-256");
    log.info("Disclosure:{}", disclosure.getDisclosure());
    log.info("Calculated hash: {}", Base64.getUrlEncoder().withoutPadding().encodeToString(disclosureHash));
  }

  @Test
  void testDisclosures() throws Exception {
    testDisclosure("WyIyR0xDNDJzS1F2ZUNmR2ZyeU5STjl3IiwgImdpdmVuX25hbWUiLCAiSm9obiJd",
      "jsu9yVulwQQlhFlM_3JlzMaSFzglhQG0DpfayQwLUK4");
    testDisclosure("WyIyR0xDNDJzS1F2ZUNmR2ZyeU5STjl3IiwiZ2l2ZW5fbmFtZSIsIkpvaG4iXQ",
      "8VHiz7qTXavxvpiTYDCSr_shkUO6qRcVXjkhEnt1os4");
    testDisclosure("WyJBSngtMDk1VlBycFR0TjRRTU9xUk9BIiwgImFkZHJlc3MiLCB7InN0cmVldF9hZGRy"
      + "ZXNzIjogIjEyMyBNYWluIFN0IiwgImxvY2FsaXR5IjogIkFueXRvd24iLCAicmVnaW9uIjogIkFueXN0YXRlIiwgImNvdW50cnkiOiAiVVMifV0",
      "XzFrzwscM6Gn6CJDc6vVK8BkMnfG8vOSKfpPIZdAfdE");
    testDisclosure("WyJsa2x4RjVqTVlsR1RQVW92TU5JdkNBIiwgIlVTIl0", "pFndjkZ_VCzmyTa6UjlZo3dh-ko8aIKQc9DlGzhaVYo");
  }

  void testDisclosure(String disclosureb64, String expectedHash) throws Exception {
    Disclosure disclosure = new Disclosure(disclosureb64);
    log.info("Disclosure: {}", disclosureb64);
    log.info("Decoded: {}", disclosure.getDisclosure());
    byte[] hash = JSONUtils.disclosureHash(disclosure, "SHA-256");
    String encodedHash = base64URLEncode(hash);
    log.info("Encoded hash: {}", encodedHash);
    if (expectedHash != null) {
      assertEquals(expectedHash, encodedHash);
    }
  }


  byte[] base64URLDecode (String data){
    return Base64.getUrlDecoder().decode(data);
  }
  String base64URLEncode (byte[] data) {
    return Base64.getUrlEncoder().withoutPadding().encodeToString(data);
  }

}
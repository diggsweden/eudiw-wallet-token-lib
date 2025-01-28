package se.digg.wallet.datatypes.mdl.data;

import se.idsec.cose.*;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;
import com.fasterxml.jackson.datatype.jsr310.JavaTimeModule;
import com.upokecenter.cbor.CBORObject;
import com.upokecenter.cbor.CBORType;
import lombok.extern.slf4j.Slf4j;
import org.bouncycastle.crypto.Digest;
import org.bouncycastle.crypto.digests.SHA256Digest;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.util.encoders.Hex;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import se.digg.wallet.datatypes.common.TokenSigningAlgorithm;

import java.io.ByteArrayInputStream;
import java.io.InputStream;
import java.math.BigInteger;
import java.security.SecureRandom;
import java.security.Security;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.time.Duration;
import java.time.LocalDate;
import java.util.*;

/**
 * Description
 */
@Slf4j
class IssuerSignedTest {

  static SecureRandom RNG;
  static ObjectMapper jsonObjectMapper;

  @BeforeAll
  static void init() {
    if (Security.getProvider("BC") == null) {
      Security.addProvider(new BouncyCastleProvider());
    }
    RNG = new SecureRandom();
    jsonObjectMapper = new ObjectMapper()
      .configure(SerializationFeature.WRITE_DATES_AS_TIMESTAMPS, false)
      .registerModule(new JavaTimeModule());
  }

  @Test
  void testSubject() throws Exception{

    IssuerSigned issuerSigned = IssuerSigned.builder()
      .nameSpace("org.iso.18013.5.1", List.of(
        IssuerSignedItem.builder()
          .digestID(4)
          .random(new BigInteger(128, RNG).toByteArray())
          .elementValue("Nisse")
          .elementIdentifier("given_name")
          .build(),
        IssuerSignedItem.builder()
          .digestID(2)
          .random(new BigInteger(128, RNG).toByteArray())
          .elementValue("Hult")
          .elementIdentifier("surname")
          .build(),
        IssuerSignedItem.builder()
          .digestID(6)
          .random(Hex.decode("14696485153f5a99856679e07a053881a18800175c34ef78bdac528cff2032b0"))
          .elementValue("Thuland")
          .elementIdentifier("family_name")
          .build()
      ))
      .nameSpace("org.iso.18013.5.1", List.of(
        IssuerSignedItem.builder()
          .digestID(4)
          .random(Hex.decode("1eee457bdea02501fe35e380bd2b8974"))
          .elementIdentifier("given_name")
          .elementValue("Inga")
          .build(),
        IssuerSignedItem.builder()
          .digestID(5)
          .random(Hex.decode("c8fb86f4dd1fb6f658c5854a193073f4"))
          .elementIdentifier("birth_date")
          .elementValue(LocalDate.of(1991,11,06))
          .build()
      ))
      .build();

    logIssuerSigned(issuerSigned);
    byte[] issuerSignedCbor = CBORUtils.CBOR_MAPPER.writeValueAsBytes(issuerSigned);
    IssuerSigned deserializedIssuerSigned = CBORUtils.CBOR_MAPPER.readValue(issuerSignedCbor, IssuerSigned.class);
    Assertions.assertEquals(issuerSigned, deserializedIssuerSigned);
  }
  @Test
  void hashValues() throws Exception{

    IssuerSigned issuerSigned = IssuerSigned.builder()
      .nameSpace("org.iso.18013.5.1", List.of(
        IssuerSignedItem.builder()
          .digestID(1)
          .random(Hex.decode("71b9e64c81edd3fd7bb7e01c1e42996c"))
          .elementIdentifier("issue_date")
          .elementValue(LocalDate.of(2024,01,12))
          .build(),
        IssuerSignedItem.builder()
          .digestID(2)
          .random(Hex.decode("51c2fcc1549601736a6585deef5d9c13"))
          .elementIdentifier("expiry_date")
          .elementValue(LocalDate.of(2025,01,12))
          .build(),
        IssuerSignedItem.builder()
          .digestID(3)
          .random(Hex.decode("dcb81876c44e92ab10c3102398f47dc2"))
          .elementIdentifier("family_name")
          .elementValue("Silverstone")
          .build(),
        IssuerSignedItem.builder()
          .digestID(4)
          .random(Hex.decode("1eee457bdea02501fe35e380bd2b8974"))
          .elementIdentifier("given_name")
          .elementValue("Inga")
          .build(),
        IssuerSignedItem.builder()
          .digestID(5)
          .random(Hex.decode("c8fb86f4dd1fb6f658c5854a193073f4"))
          .elementIdentifier("birth_date")
          .elementValue(LocalDate.of(1991,11,06))
          .build(),
        IssuerSignedItem.builder()
          .digestID(6)
          .random(Hex.decode("22655e9974500c618a237d0704a72de0"))
          .elementIdentifier("issuing_country")
          .elementValue("US")
          .build(),
        IssuerSignedItem.builder()
          .digestID(7)
          .random(Hex.decode("6d6cff820531cad49ac7bfc5a82ce810"))
          .elementIdentifier("document_number")
          .elementValue("12345678")
          .build()
      ))
      .build();

    logIssuerSigned(issuerSigned);
    byte[] issuerSignedCbor = CBORUtils.CBOR_MAPPER.writeValueAsBytes(issuerSigned);
    IssuerSigned deserializedIssuerSigned = CBORUtils.CBOR_MAPPER.readValue(issuerSignedCbor, IssuerSigned.class);
    Assertions.assertEquals(issuerSigned, deserializedIssuerSigned);

    logIssuerSigned(issuerSigned);
    List<IssuerSignedItem> issuerSignedItems = issuerSigned.getNameSpaces().get("org.iso.18013.5.1");

    List<byte[]> expectedHashValues = Arrays.asList(new byte[]{},
      Hex.decode("ab92f0509e09cbc333066011eceeb95bfe0d8b14a5dca9269f5a6c9aea1c0997"),
      Hex.decode("bbb0fedefafe36b2e0df38a0ba753310a16a600c86e6c03e7dfbe60e3471676e"),
      Hex.decode("b63819e1a19161a84eecf0f45f75e8fcb797eba7e1e017fd97e2a32dcef118e8"),
      Hex.decode("117fae5f77551db5ba69087523225aa1664f9271b349f71f9496a275ab2680eb"),
      Hex.decode("283bd5c8c537e7c2ded27e939156f673405b85b48c270a6cc2d3cb36266b4d1f"),
      Hex.decode("056732700269c2ed070c430abbd850d09663f1934e37e1c65b87afebb7555a81"),
      Hex.decode("7c011d0dfeb153ed728f9171486e618aba8a2bee8e36322664016d0fce761143"),
      Hex.decode("7234f61d8824a319f058ffbd8ea3bfebe0fe77af47f545b6c63a435ab92796f0")
    );
    for (IssuerSignedItem item : issuerSignedItems) {
      byte[] bytes = sha256Hash(item.toBeHashedBytes());
      Assertions.assertArrayEquals(expectedHashValues.get(item.getDigestID()), bytes);
    }
  }


  private void logIssuerSigned(IssuerSigned issuerSigned) throws Exception {
    byte[] issuerSignedCbor = CBORUtils.CBOR_MAPPER.writeValueAsBytes(issuerSigned);
    log.info("CBOR encoded:\n{}", Hex.toHexString(issuerSignedCbor));
    log.info("Data content:\n{}", CBORUtils.cborToPrettyJson(issuerSignedCbor));
    log.info("Inspecting issuer signed items");
    for (String nameSpace : issuerSigned.getNameSpaces().keySet()){
      List<IssuerSignedItem> issuerSignedItems = issuerSigned.getNameSpaces().get(nameSpace);
      for (IssuerSignedItem item : issuerSignedItems) {
        logIssuerSignedItem(item, nameSpace);
      }
    }
  }

  @Test
  void testSignedIssuerSigned() throws Exception {
    IssuerSigned issuerSigned = IssuerSigned.builder()
      .nameSpace("org.iso.18013.5.1", List.of(
        IssuerSignedItem.builder()
          .digestID(1)
          .random(Hex.decode("71b9e64c81edd3fd7bb7e01c1e42996c"))
          .elementIdentifier("issue_date")
          .elementValue(LocalDate.of(2024,01,12))
          .build(),
        IssuerSignedItem.builder()
          .digestID(2)
          .random(Hex.decode("51c2fcc1549601736a6585deef5d9c13"))
          .elementIdentifier("expiry_date")
          .elementValue(LocalDate.of(2025,01,12))
          .build(),
        IssuerSignedItem.builder()
          .digestID(3)
          .random(Hex.decode("dcb81876c44e92ab10c3102398f47dc2"))
          .elementIdentifier("family_name")
          .elementValue("Silverstone")
          .build(),
        IssuerSignedItem.builder()
          .digestID(4)
          .random(Hex.decode("1eee457bdea02501fe35e380bd2b8974"))
          .elementIdentifier("given_name")
          .elementValue("Inga")
          .build(),
        IssuerSignedItem.builder()
          .digestID(5)
          .random(Hex.decode("c8fb86f4dd1fb6f658c5854a193073f4"))
          .elementIdentifier("birth_date")
          .elementValue(LocalDate.of(1991,11,06))
          .build(),
        IssuerSignedItem.builder()
          .digestID(6)
          .random(Hex.decode("22655e9974500c618a237d0704a72de0"))
          .elementIdentifier("issuing_country")
          .elementValue("US")
          .build(),
        IssuerSignedItem.builder()
          .digestID(7)
          .random(Hex.decode("6d6cff820531cad49ac7bfc5a82ce810"))
          .elementIdentifier("document_number")
          .elementValue("12345678")
          .build()
      ))
      .issuerAuthInput(TestCredentials.issuerCredential,
        TokenSigningAlgorithm.ECDSA_256,
        COSEKey.generateKey(AlgorithmID.ECDSA_256).AsPublicKey(),
        Duration.ofDays(1), null)
      .build();

    byte[] issuerSignedBytes = CBORUtils.CBOR_MAPPER.writeValueAsBytes(issuerSigned);
    log.info("Signed IssuerSigned: \n{}", Hex.toHexString(issuerSignedBytes));

    IssuerSigned parsedIssuerSigned = IssuerSigned.deserialize(issuerSignedBytes);
    Assertions.assertEquals(issuerSigned, parsedIssuerSigned);
    Sign1COSEObject parsedSignatureObject = (Sign1COSEObject) Sign1COSEObject.DecodeFromBytes(parsedIssuerSigned.getIssuerAuth(), COSEObjectTag.Sign1);
    CBORObject unprotectedAttributes = parsedSignatureObject.getUnprotectedAttributes();
    CBORObject x5chain = unprotectedAttributes.get(HeaderKeys.x5chain.AsCBOR());
    CBORObject signingCertObject;
    if (x5chain.getType().equals(CBORType.ByteString)) {
      signingCertObject = x5chain;
    } else {
      signingCertObject = x5chain.get(0);
    }
    CertificateFactory certFactory = CertificateFactory.getInstance("X.509");
    InputStream in = new ByteArrayInputStream(signingCertObject.GetByteString());
    X509Certificate signingCert = (X509Certificate) certFactory.generateCertificate(in);
    Assertions.assertEquals(TestCredentials.issuerCredential.getCertificate(), signingCert);
    boolean valid = parsedSignatureObject.validate(new COSEKey(signingCert.getPublicKey(), null));
    Assertions.assertTrue(valid);
    byte[] parsedMsoBytes = parsedSignatureObject.GetContent();
    MobileSecurityObject parsedMso = MobileSecurityObject.deserialize(parsedMsoBytes);
    int sdf=0;
  }

  private void logIssuerSignedItem(IssuerSignedItem item, String nameSpace) throws Exception {
    log.info("Examining namespace: {}", nameSpace);
    byte[] toBeHashedBytes = CBORUtils.CBOR_MAPPER.writeValueAsBytes(item);
    //IssuerSignedItem.TempStorage tempStorage = new IssuerSignedItem.TempStorage(item);
    log.info("Issuer signed item data:\n{}", CBORUtils.cborToPrettyJson(toBeHashedBytes));
    log.info("To be hashed bytes: {}", Hex.toHexString(toBeHashedBytes));
    log.info("Hash: {}", Hex.toHexString(sha256Hash(toBeHashedBytes)));
  }

  byte[] sha256Hash(byte[] toBeHashedBytes) throws Exception {
    Digest digest = new SHA256Digest();
    byte[] hash = new byte[digest.getDigestSize()];
    digest.update(toBeHashedBytes, 0, toBeHashedBytes.length);
    digest.doFinal(hash, 0);
    return hash;
  }

  @Test
  void testIsoNameSpaceExample()  throws Exception {
    // To be deleted
    byte[] evcExample = Base64.getUrlDecoder().decode(
      "omppc3N1ZXJBdXRohEOhASahGCFZAukwggLlMIICaqADAgECAhRoQu0mnaibjqEFrDO7g1RxBIyzBDAKBggqhkjOPQQDAjBcMR4wHAYDVQQDDBVQSUQgSXNzdWVyIENBIC0gVVQgMDExLTArBgNVBAoMJEVVREkgV2FsbGV0IFJlZmVyZW5jZSBJbXBsZW1lbnRhdGlvbjELMAkGA1UEBhMCVVQwHhcNMjQwNzAxMTAwMzA2WhcNMjUwOTI0MTAwMzA1WjBUMRYwFAYDVQQDDA1QSUQgRFMgLSAwMDAyMS0wKwYDVQQKDCRFVURJIFdhbGxldCBSZWZlcmVuY2UgSW1wbGVtZW50YXRpb24xCzAJBgNVBAYTAlVUMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE66T6UUJ8d2wrkB_g0zroSJ_boX3LL1wToHmFgFCaVQoS5OQ6gx64rPFJ36iBrfXBZbWUOvORiayYAE6H1XXyVKOCARAwggEMMB8GA1UdIwQYMBaAFLNsuJEXHNekGmYxh0Lhi8BAzJUbMBYGA1UdJQEB_wQMMAoGCCuBAgIAAAECMEMGA1UdHwQ8MDowOKA2oDSGMmh0dHBzOi8vcHJlcHJvZC5wa2kuZXVkaXcuZGV2L2NybC9waWRfQ0FfVVRfMDEuY3JsMB0GA1UdDgQWBBQEfQ5D1-0ZE9VvaFJOS-fzBhMSyjAOBgNVHQ8BAf8EBAMCB4AwXQYDVR0SBFYwVIZSaHR0cHM6Ly9naXRodWIuY29tL2V1LWRpZ2l0YWwtaWRlbnRpdHktd2FsbGV0L2FyY2hpdGVjdHVyZS1hbmQtcmVmZXJlbmNlLWZyYW1ld29yazAKBggqhkjOPQQDAgNpADBmAjEAkfm_P8cc8y1BtYvC4tH1-iB1spuGpMRpYvxZZxpbhoMZ10fyDDwXC-knmtzkP0p7AjEA2l-9N2LXnG-vqaO2rCgylMXMV8L_HHB-fW_WThZoljQc5_XuOihslQXdIyY-BTvbWQJZ2BhZAlSmZ2RvY1R5cGV3ZXUuZXVyb3BhLmVjLmV1ZGkucGlkLjFndmVyc2lvbmMxLjBsdmFsaWRpdHlJbmZvo2ZzaWduZWTAdDIwMjQtMTEtMTlUMDc6NDk6MjJaaXZhbGlkRnJvbcB0MjAyNC0xMS0xOVQwNzo0OToyMlpqdmFsaWRVbnRpbMB0MjAyNS0wMi0xN1QwMDowMDowMFpsdmFsdWVEaWdlc3RzoXdldS5ldXJvcGEuZWMuZXVkaS5waWQuMagAWCCGNciAN9igIeefh-AQ24CTD1s5ORel1XP6hPVz3K3QmQFYINawr_Kdw9G05xrGf1TFQD85TNYkdT60thyE9MrcSoBNAlggBq91GsYxZmah6lMMfvL9CizLxzuw1uAgwDtRIk42pJ4DWCBtTtVrgul7w-q4MZQ0hEMADThV8av9NB3qWvYnsUA8JwRYIK3lQYLuc_Kqz0Tdwh1AYG3GIGEVx3LGmbYsdHBjNP7wBVggGOM7qlE0zCuypNJlRA7kji-bajVG0AjFyb9hH8W8hNsGWCBVss1tDxnZKwHgGstmqCOXquTRUc0mFGIlXPMOS_o07wdYIAju4pNtAereVAFZs5P73nx0gLd7gDEnCrINUFfPFvIUbWRldmljZUtleUluZm-haWRldmljZUtleaQBAiABIVggGrIEwKcz8CGMXiHuLu9_lhhjS3o7CpFMAQig0fsjVAgiWCDtwkQGOvgl5Qwbrf8iHmhkFE_8Xg0OrYUwCNh5jgzaAm9kaWdlc3RBbGdvcml0aG1nU0hBLTI1NlhAq7N4-Y7IRpOmwhoUix4mNNXKwAzyOAPnRsqXofpjWWEGvGoFI8n3u35SoRYRDFHBBhYOH_INJG5tswXXMeKnjmpuYW1lU3BhY2VzoXdldS5ldXJvcGEuZWMuZXVkaS5waWQuMYjYGFhvpGZyYW5kb21YIGVoS8sXJh-ZQ_LQATusxoxaTHZ4Rwdcpd9KWWSu_ULqaGRpZ2VzdElEAGxlbGVtZW50VmFsdWXZA-xqMjAyNC0xMS0xOXFlbGVtZW50SWRlbnRpZmllcm1pc3N1YW5jZV9kYXRl2BhYZqRmcmFuZG9tWCDdaC8sDcj0xRude-HNRYyYSk4DfYcZkqOT_f93BTQPWWhkaWdlc3RJRAFsZWxlbWVudFZhbHVlYkZDcWVsZW1lbnRJZGVudGlmaWVyb2lzc3VpbmdfY291bnRyedgYWGWkZnJhbmRvbVgg2P2y7jnQZSixYYHTEc23U34Hv16jjF98VE_KTdnd1K5oZGlnZXN0SUQCbGVsZW1lbnRWYWx1ZWZKb2hubnlxZWxlbWVudElkZW50aWZpZXJqZ2l2ZW5fbmFtZdgYWGCkZnJhbmRvbVgge5HlU0GvXGjGRtFznX_gBDoDNN221Usojn5f30IZiztoZGlnZXN0SUQDbGVsZW1lbnRWYWx1ZfVxZWxlbWVudElkZW50aWZpZXJrYWdlX292ZXJfMTjYGFhspGZyYW5kb21YIBkLoFfpzjJsL3c92pTNT78-AabhwNJnRl4VO6VGKjfCaGRpZ2VzdElEBGxlbGVtZW50VmFsdWXZA-xqMTk4Ni0wMi0yMXFlbGVtZW50SWRlbnRpZmllcmpiaXJ0aF9kYXRl2BhYbaRmcmFuZG9tWCBwu_EZgKggzK40rVlY84u4yF2fT9ZO_4gdUa5tZuCInWhkaWdlc3RJRAVsZWxlbWVudFZhbHVl2QPsajIwMjUtMDItMTdxZWxlbWVudElkZW50aWZpZXJrZXhwaXJ5X2RhdGXYGFhnpGZyYW5kb21YIBRpZIUVP1qZhWZ54HoFOIGhiAAXXDTveL2sUoz_IDKwaGRpZ2VzdElEBmxlbGVtZW50VmFsdWVnVGh1bGFuZHFlbGVtZW50SWRlbnRpZmllcmtmYW1pbHlfbmFtZdgYWHWkZnJhbmRvbVggznvLq6zlDkRQIKVzyWWzGdcWxgCa3Xl8mlrXBHwEFYNoZGlnZXN0SUQHbGVsZW1lbnRWYWx1ZW9UZXN0IFBJRCBpc3N1ZXJxZWxlbWVudElkZW50aWZpZXJxaXNzdWluZ19hdXRob3JpdHk=");

    byte[] mdlExample = Base64.getUrlDecoder().decode(
      "omdkb2NUeXBldW9yZy5pc28uMTgwMTMuNS4xLm1ETGxpc3N1ZXJTaWduZWSiam5hbWVTcGFjZXOhcW9yZy5pc28uMTgwMTMuNS4xiNgYWFukaGRpZ2VzdElEAWZyYW5kb21QcbnmTIHt0_17t-AcHkKZbHFlbGVtZW50SWRlbnRpZmllcmppc3N1ZV9kYXRlbGVsZW1lbnRWYWx1ZdkD7GoyMDI0LTAxLTEy2BhYXKRoZGlnZXN0SUQCZnJhbmRvbVBRwvzBVJYBc2plhd7vXZwTcWVsZW1lbnRJZGVudGlmaWVya2V4cGlyeV9kYXRlbGVsZW1lbnRWYWx1ZdkD7GoyMDI1LTAxLTEy2BhYWqRoZGlnZXN0SUQDZnJhbmRvbVDcuBh2xE6SqxDDECOY9H3CcWVsZW1lbnRJZGVudGlmaWVya2ZhbWlseV9uYW1lbGVsZW1lbnRWYWx1ZWtTaWx2ZXJzdG9uZdgYWFKkaGRpZ2VzdElEBGZyYW5kb21QHu5Fe96gJQH-NeOAvSuJdHFlbGVtZW50SWRlbnRpZmllcmpnaXZlbl9uYW1lbGVsZW1lbnRWYWx1ZWRJbmdh2BhYW6RoZGlnZXN0SUQFZnJhbmRvbVDI-4b03R-29ljFhUoZMHP0cWVsZW1lbnRJZGVudGlmaWVyamJpcnRoX2RhdGVsZWxlbWVudFZhbHVl2QPsajE5OTEtMTEtMDbYGFhVpGhkaWdlc3RJRAZmcmFuZG9tUCJlXpl0UAxhiiN9BwSnLeBxZWxlbWVudElkZW50aWZpZXJvaXNzdWluZ19jb3VudHJ5bGVsZW1lbnRWYWx1ZWJVU9gYWFukaGRpZ2VzdElEB2ZyYW5kb21QbWz_ggUxytSax7_FqCzoEHFlbGVtZW50SWRlbnRpZmllcm9kb2N1bWVudF9udW1iZXJsZWxlbWVudFZhbHVlaDEyMzQ1Njc42BhYoqRoZGlnZXN0SUQIZnJhbmRvbVBbSwOg91lMspu_ctBa2uqgcWVsZW1lbnRJZGVudGlmaWVycmRyaXZpbmdfcHJpdmlsZWdlc2xlbGVtZW50VmFsdWWBo3V2ZWhpY2xlX2NhdGVnb3J5X2NvZGVhQWppc3N1ZV9kYXRl2QPsajIwMjMtMDEtMDFrZXhwaXJ5X2RhdGXZA-xqMjA0My0wMS0wMWppc3N1ZXJBdXRohEOhASahGCFZAWEwggFdMIIBBKADAgECAgYBjJHZwhkwCgYIKoZIzj0EAwIwNjE0MDIGA1UEAwwrSjFGd0pQODdDNi1RTl9XU0lPbUpBUWM2bjVDUV9iWmRhRko1R0RuVzFSazAeFw0yMzEyMjIxNDA2NTZaFw0yNDEwMTcxNDA2NTZaMDYxNDAyBgNVBAMMK0oxRndKUDg3QzYtUU5fV1NJT21KQVFjNm41Q1FfYlpkYUZKNUdEblcxUmswWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAAQCilV5ugmlhHJzDVgqSRE5d8KkoQqX1jVg8WE4aPjFODZQ66fFPFIhWRP3ioVUi67WGQSgTY3F6Vmjf7JMVQ4MMAoGCCqGSM49BAMCA0cAMEQCIGcWNJwFy8RGV4uMwK7k1vEkqQ2xr-BCGRdN8OZur5PeAiBVrNuxV1C9mCW5z2clhDFaXNdP2Lp_7CBQrHQoJhuPcNgYWQHopWd2ZXJzaW9uYzEuMG9kaWdlc3RBbGdvcml0aG1nU0hBLTI1Nmx2YWx1ZURpZ2VzdHOhcW9yZy5pc28uMTgwMTMuNS4xqAFYIKuS8FCeCcvDMwZgEezuuVv-DYsUpdypJp9abJrqHAmXAlggu7D-3vr-NrLg3zigunUzEKFqYAyG5sA-ffvmDjRxZ24DWCC2OBnhoZFhqE7s8PRfdej8t5frp-HgF_2X4qMtzvEY6ARYIBF_rl93VR21umkIdSMiWqFmT5Jxs0n3H5SWonWrJoDrBVggKDvVyMU358Le0n6TkVb2c0BbhbSMJwpswtPLNiZrTR8GWCAFZzJwAmnC7QcMQwq72FDQlmPxk0434cZbh6_rt1VagQdYIHwBHQ3-sVPtco-RcUhuYYq6iivujjYyJmQBbQ_OdhFDCFggcjT2HYgkoxnwWP-9jqO_6-D-d69H9UW2xjpDWrknlvBnZG9jVHlwZXVvcmcuaXNvLjE4MDEzLjUuMS5tRExsdmFsaWRpdHlJbmZvo2ZzaWduZWTAdDIwMjQtMDEtMTJUMDA6MTA6MDVaaXZhbGlkRnJvbcB0MjAyNC0wMS0xMlQwMDoxMDowNVpqdmFsaWRVbnRpbMB0MjAyNS0wMS0xMlQwMDoxMDowNVpYQHFzEb09NFyFlj533FE_1B9I2rku90K52ar64Id1CyOUXWXzhINeVfoJU1cfxgCT2CX1369cGd_TQxSjhVx8bpY");


    log.info("EWC example:\n{}", Hex.toHexString(evcExample));
    log.info("mDL example Hex:\n{}", Hex.toHexString(mdlExample));
  }
}
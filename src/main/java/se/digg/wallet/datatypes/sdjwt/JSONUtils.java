// SPDX-FileCopyrightText: 2024 Digg - Agency for Digital Government
//
// SPDX-License-Identifier: EUPL-1.2

package se.digg.wallet.datatypes.sdjwt;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;
import com.fasterxml.jackson.datatype.jsr310.JavaTimeModule;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.RSAKey;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.ECParameterSpec;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;
import org.bouncycastle.jce.ECNamedCurveTable;
import org.bouncycastle.jce.spec.ECNamedCurveSpec;
import se.digg.wallet.datatypes.sdjwt.data.Disclosure;

public class JSONUtils {

  public static final ObjectMapper JSON_MAPPER = new ObjectMapper()
    .configure(SerializationFeature.WRITE_DATES_AS_TIMESTAMPS, false)
    .registerModule(new JavaTimeModule())
    .setSerializationInclusion(JsonInclude.Include.NON_NULL);

  public static String disclosureHashString(
    Disclosure disclosure,
    String hashAlgo
  ) throws NoSuchAlgorithmException {
    return base64URLString(disclosureHash(disclosure, hashAlgo));
  }

  public static byte[] disclosureHash(Disclosure disclosure, String hashAlgo)
    throws NoSuchAlgorithmException {
    return hash(
      base64URLString(
        disclosure.getDisclosure().getBytes(StandardCharsets.UTF_8)
      ).getBytes(StandardCharsets.UTF_8),
      hashAlgo
    );
  }

  public static String base64URLString(byte[] bytes) {
    return Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);
  }

  public static byte[] hash(byte[] input, String algo)
    throws NoSuchAlgorithmException {
    MessageDigest digest = MessageDigest.getInstance(algo);
    return digest.digest(input);
  }

  public static String b64UrlHash(byte[] input, String alg)
    throws NoSuchAlgorithmException {
    return base64URLString(hash(input, alg));
  }

  public static JWK getJWKfromPublicKey(PublicKey publicKey)
    throws NoSuchAlgorithmException {
    if (publicKey instanceof RSAPublicKey) {
      return new RSAKey.Builder((RSAPublicKey) publicKey).build();
    }
    if (publicKey instanceof ECPublicKey ecPublicKey) {
      ECParameterSpec params = ecPublicKey.getParams();
      return new ECKey.Builder(
        Curve.forECParameterSpec(params),
        (ECPublicKey) publicKey
      ).build();
    }
    throw new NoSuchAlgorithmException("Public key type not supported");
  }

  public static PublicKey getPublicKeyFromJWK(JWK jwk) throws JOSEException {
    if (jwk instanceof RSAKey) {
      return ((RSAKey) jwk).toRSAPublicKey();
    }
    if (jwk instanceof ECKey) {
      return ((ECKey) jwk).toECPublicKey();
    }
    throw new IllegalArgumentException("Unsupported JWK type");
  }
}

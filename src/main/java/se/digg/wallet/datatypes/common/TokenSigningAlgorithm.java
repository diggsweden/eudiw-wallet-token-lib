// SPDX-FileCopyrightText: 2024 Digg - Agency for Digital Government
//
// SPDX-License-Identifier: EUPL-1.2

package se.digg.wallet.datatypes.common;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSSigner;
import com.nimbusds.jose.JWSVerifier;
import com.nimbusds.jose.crypto.ECDSASigner;
import com.nimbusds.jose.crypto.ECDSAVerifier;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jose.crypto.RSASSAVerifier;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.RSAPublicKey;
import java.util.Arrays;
import lombok.AllArgsConstructor;
import lombok.Getter;
import se.idsec.cose.AlgorithmID;
import se.idsec.cose.COSEKey;

/**
 * Supported Mdl
 */
@Getter
@AllArgsConstructor
public enum TokenSigningAlgorithm {
  ECDSA_256(
    AlgorithmID.ECDSA_256,
    TokenDigestAlgorithm.SHA_256,
    JWSAlgorithm.ES256
  ),
  ECDSA_384(
    AlgorithmID.ECDSA_384,
    TokenDigestAlgorithm.SHA_384,
    JWSAlgorithm.ES384
  ),
  ECDSA_512(
    AlgorithmID.ECDSA_512,
    TokenDigestAlgorithm.SHA_512,
    JWSAlgorithm.ES512
  ),
  RSA_PSS_256(
    AlgorithmID.RSA_PSS_256,
    TokenDigestAlgorithm.SHA_256,
    JWSAlgorithm.PS256
  ),
  RSA_PSS_384(
    AlgorithmID.RSA_PSS_384,
    TokenDigestAlgorithm.SHA_384,
    JWSAlgorithm.PS384
  ),
  RSA_PSS_512(
    AlgorithmID.RSA_PSS_512,
    TokenDigestAlgorithm.SHA_512,
    JWSAlgorithm.PS512
  );

  private final AlgorithmID algorithmID;
  private final TokenDigestAlgorithm digestAlgorithm;
  private final JWSAlgorithm jwsAlgorithm;

  /**
   * Retrieves the supported TokenSigningAlgorithm based on the provided signing key.
   *
   * @param signingKey the signing key used to determine the TokenSigningAlgorithm
   * @return the TokenSigningAlgorithm that corresponds to the signing key
   */
  public static TokenSigningAlgorithm fromCOSEKey(COSEKey signingKey)
    throws NoSuchAlgorithmException {
    return Arrays.stream(values())
      .filter(
        tokenSigningAlgorithm ->
          signingKey.HasAlgorithmID(tokenSigningAlgorithm.getAlgorithmID())
      )
      .findFirst()
      .orElseThrow(
        () ->
          new NoSuchAlgorithmException(
            "No supported algorithm match the provided key"
          )
      );
  }

  public static TokenSigningAlgorithm fromJWSAlgorithm(
    JWSAlgorithm jwsAlgorithm
  ) throws NoSuchAlgorithmException {
    return Arrays.stream(values())
      .filter(
        signingAlgorithm ->
          signingAlgorithm.getJwsAlgorithm().equals(jwsAlgorithm)
      )
      .findFirst()
      .orElseThrow(
        () ->
          new NoSuchAlgorithmException(
            "No supported algorithm match the specified JWSAlgorithm"
          )
      );
  }

  public JWSSigner jwsSigner(PrivateKey privateKey) throws JOSEException {
    return switch (this) {
      case ECDSA_256, ECDSA_384, ECDSA_512 -> new ECDSASigner(
        (ECPrivateKey) privateKey
      );
      case RSA_PSS_256, RSA_PSS_384, RSA_PSS_512 -> new RSASSASigner(
        privateKey
      );
    };
  }

  public JWSVerifier jwsVerifier(PublicKey publicKey) throws JOSEException {
    return switch (this) {
      case ECDSA_256, ECDSA_384, ECDSA_512 -> new ECDSAVerifier(
        (ECPublicKey) publicKey
      );
      case RSA_PSS_256, RSA_PSS_384, RSA_PSS_512 -> new RSASSAVerifier(
        (RSAPublicKey) publicKey
      );
    };
  }
}

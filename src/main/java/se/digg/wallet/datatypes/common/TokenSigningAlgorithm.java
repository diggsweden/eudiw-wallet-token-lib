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
import se.digg.cose.AlgorithmID;
import se.digg.cose.COSEKey;

/**
 * Supported Mdl
 */
@Getter
@AllArgsConstructor
public enum TokenSigningAlgorithm {
  /** ECDSA with SHA 256 */
  ECDSA_256(
    AlgorithmID.ECDSA_256,
    TokenDigestAlgorithm.SHA_256,
    JWSAlgorithm.ES256
  ),
  /** ECDSA with SHA 384 */
  ECDSA_384(
    AlgorithmID.ECDSA_384,
    TokenDigestAlgorithm.SHA_384,
    JWSAlgorithm.ES384
  ),
  /** ECDSA with SHA 512 */
  ECDSA_512(
    AlgorithmID.ECDSA_512,
    TokenDigestAlgorithm.SHA_512,
    JWSAlgorithm.ES512
  ),
  /** RSA PSS with SHA 256 */
  RSA_PSS_256(
    AlgorithmID.RSA_PSS_256,
    TokenDigestAlgorithm.SHA_256,
    JWSAlgorithm.PS256
  ),
  /** RSA PSS with SHA 384 */
  RSA_PSS_384(
    AlgorithmID.RSA_PSS_384,
    TokenDigestAlgorithm.SHA_384,
    JWSAlgorithm.PS384
  ),
  /** RSA PSS with SHA 512 */
  RSA_PSS_512(
    AlgorithmID.RSA_PSS_512,
    TokenDigestAlgorithm.SHA_512,
    JWSAlgorithm.PS512
  );

  /** Algorithm ID */
  private final AlgorithmID algorithmID;
  /** Digest algorithm */
  private final TokenDigestAlgorithm digestAlgorithm;
  /** JWS algorithm */
  private final JWSAlgorithm jwsAlgorithm;

  /**
   * Retrieves the supported TokenSigningAlgorithm based on the provided signing key.
   *
   * @param signingKey the signing key used to determine the TokenSigningAlgorithm
   * @return the TokenSigningAlgorithm that corresponds to the signing key
   * @throws NoSuchAlgorithmException if no supported algorithm matches the given COSE key
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

  /**
   * Maps a given {@code JWSAlgorithm} to a corresponding {@code TokenSigningAlgorithm}.
   *
   * @param jwsAlgorithm the JWSAlgorithm that needs to be mapped
   * @return the TokenSigningAlgorithm that corresponds to the specified JWSAlgorithm
   * @throws NoSuchAlgorithmException if no supported TokenSigningAlgorithm matches the specified JWSAlgorithm
   */
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

  /**
   * Creates and returns a {@link JWSSigner} based on the provided private key and the current signing algorithm.
   *
   * @param privateKey the private key used for creating the signer. It must match the algorithm type expected by the signer.
   *                   For EC algorithms, the key must be of type {@link ECPrivateKey}.
   * @return an instance of {@link JWSSigner} that corresponds to the current signing algorithm.
   * @throws JOSEException if an error occurs during the creation of the signer, such as invalid key type or unsupported algorithm.
   */
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

  /**
   * Creates a JWSVerifier instance based on the algorithm type.
   *
   * This method returns a specific verifier implementation depending on the token
   * signing algorithm (e.g., ECDSA or RSA_PSS). It requires a public key and throws
   * a JOSEException if the verifier cannot be instantiated.
   *
   * @param publicKey the public key used to verify the JWS signature.
   * @return a JWSVerifier instance tailored to the specified algorithm type.
   * @throws JOSEException if a JWSVerifier instance cannot be created.
   */
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

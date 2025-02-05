// SPDX-FileCopyrightText: 2024 Digg - Agency for Digital Government
//
// SPDX-License-Identifier: EUPL-1.2

package se.digg.wallet.datatypes.common;

import java.io.IOException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.Security;
import java.security.cert.CertificateException;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.gen.ECKeyGenerator;
import com.nimbusds.jose.jwk.gen.RSAKeyGenerator;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import se.swedenconnect.security.credential.KeyStoreCredential;
import se.swedenconnect.security.credential.PkiCredential;

public class TestCredentials {

  public static final PkiCredential p256_issuerCredential;
  public static final PkiCredential rsa_issuerCredential;
  public static final ECKey p256_walletKey;
  public static final RSAKey rsa_walletKey;


  static {
    if (Security.getProvider("BC") == null) {
      Security.addProvider(new BouncyCastleProvider());
    }
    try {
      KeyStore issuerKeyStore = KeyStore.getInstance(KeyStore.getDefaultType());
      issuerKeyStore.load(
        TestCredentials.class.getResourceAsStream("/pid-issuer.jks"),
        "Test1234".toCharArray()
      );
      p256_issuerCredential = new KeyStoreCredential(
        issuerKeyStore,
        "pid-issuer",
        "Test1234".toCharArray()
      );
      rsa_issuerCredential = new KeyStoreCredential(
        issuerKeyStore,
        "pid-issuer-rsa",
        "Test1234".toCharArray()
      );
      p256_walletKey =  new ECKeyGenerator(Curve.P_256).generate();
      rsa_walletKey = new RSAKeyGenerator(3072).generate();

    } catch (
      KeyStoreException
      | CertificateException
      | IOException
      | NoSuchAlgorithmException
      | JOSEException e
    ) {
      throw new RuntimeException(e);
    }
  }
}

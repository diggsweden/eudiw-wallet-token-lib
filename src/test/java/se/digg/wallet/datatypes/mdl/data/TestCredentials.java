// SPDX-FileCopyrightText: 2024 Digg - Agency for Digital Government
//
// SPDX-License-Identifier: EUPL-1.2

package se.digg.wallet.datatypes.mdl.data;

import java.io.IOException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.Security;
import java.security.cert.CertificateException;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import se.swedenconnect.security.credential.KeyStoreCredential;
import se.swedenconnect.security.credential.PkiCredential;

public class TestCredentials {

  public static final PkiCredential issuerCredential;

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
      issuerCredential = new KeyStoreCredential(
        issuerKeyStore,
        "pid-issuer",
        "Test1234".toCharArray()
      );
      int sdf = 0;
    } catch (
      KeyStoreException
      | CertificateException
      | IOException
      | NoSuchAlgorithmException e
    ) {
      throw new RuntimeException(e);
    }
  }
}

// SPDX-FileCopyrightText: 2024 IDsec Solutions AB
//
// SPDX-License-Identifier: BSD-3-Clause

package se.idsec.cose;

import java.security.Provider;

/**
 * Specify which JCA Provider to use for signing and verifying messages
 */
public class CryptoContext {

  private Provider provider;

  public CryptoContext(Provider provider) {
    this.provider = provider;
  }

  public Provider getProvider() {
    return provider;
  }

  public void setProvider(Provider provider) {
    this.provider = provider;
  }
}

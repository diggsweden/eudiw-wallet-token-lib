// SPDX-FileCopyrightText: 2024 IDsec Solutions AB
//
// SPDX-License-Identifier: BSD-3-Clause

package se.idsec.cose;

/**
 *
 * @author jimsch
 */
public enum COSEObjectTag {
  Unknown(0),
  Encrypt0(16),
  Encrypt(96),
  Sign1(18),
  Sign(98),
  MAC(97),
  MAC0(17);

  public final int value;

  COSEObjectTag(int i) {
    value = i;
  }

  public static COSEObjectTag FromInt(int i) throws CoseException {
    for (COSEObjectTag m : COSEObjectTag.values()) {
      if (i == m.value) return m;
    }
    throw new CoseException("Not a COSEObject tag number");
  }
}

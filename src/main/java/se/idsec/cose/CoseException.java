// SPDX-FileCopyrightText: 2024 IDsec Solutions AB
//
// SPDX-License-Identifier: BSD-3-Clause

package se.idsec.cose;

/**
 *
 * @author jimsch
 */
public class CoseException extends Exception {

  public CoseException(String message) {
    super(message);
  }

  public CoseException(String message, Exception ex) {
    super(message, ex);
  }
}

// SPDX-FileCopyrightText: 2025 Digg - Agency for Digital Government
//
// SPDX-License-Identifier: EUPL-1.2

package se.digg.wallet.datatypes.mdl.data;

import lombok.AllArgsConstructor;
import lombok.Getter;

/**
 * Enum representing different types of document identifiers.
 * Each enum constant has an associated identifier string.
 */
@Getter
@AllArgsConstructor
public enum MdlDocType {
  /** Standard mDL document type identifier */
  mDL("org.iso.18013.5.1.mDL"),
  /** EDUI Wallet document type identifier */
  EUDI_WALLET_PID("eu.europa.ec.eudi.pid.1");

  /**
   * The unique identifier string associated with the document type.
   */
  private final String id;
}

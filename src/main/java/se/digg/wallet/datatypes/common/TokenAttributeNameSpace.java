// SPDX-FileCopyrightText: 2025 Digg - Agency for Digital Government
//
// SPDX-License-Identifier: EUPL-1.2

package se.digg.wallet.datatypes.common;

import lombok.AllArgsConstructor;
import lombok.Getter;

/**
 * Enum representing namespaces associated with token attributes.
 *
 * Each namespace is identified by a unique string identifier (id),
 * which groups attributes under a specific category or standard.
 * This allows for better organization and management of token attributes
 * across different implementations or frameworks.
 */
@Getter
@AllArgsConstructor
public enum TokenAttributeNameSpace {
  /** EUDI wallet PID attribute name space */
  EUDI_WALLET_PID("eu.europa.ec.eudi.pid.1"),
  /** Mdoc mDL attribute namespace */
  MDOC_MDL("org.iso.18013.5.1");

  /**
   * The string identifier representing a namespace associated with token attributes.
   */
  final String id;
}

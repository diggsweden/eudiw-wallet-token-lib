// SPDX-FileCopyrightText: 2025 Digg - Agency for Digital Government
//
// SPDX-License-Identifier: EUPL-1.2

package se.digg.wallet.datatypes.common;

import lombok.AllArgsConstructor;
import lombok.Getter;

@Getter
@AllArgsConstructor
public enum TokenAttributeNameSpace {
  EUDI_WALLET_PID("eu.europa.ec.eudi.pid.1"),
  MDOC_MDL("org.iso.18013.5.1");

  final String id;
}

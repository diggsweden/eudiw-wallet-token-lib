package se.digg.wallet.datatypes.common;

import lombok.AllArgsConstructor;
import lombok.Getter;

@Getter
@AllArgsConstructor
public enum TokenAttributeNameSpace {
  EUDI_WALLET_PID("eu.europa.ec.eudi.pid.1"),
  MDOC_MDL("org.iso.18013.5.1");

  String id;
}

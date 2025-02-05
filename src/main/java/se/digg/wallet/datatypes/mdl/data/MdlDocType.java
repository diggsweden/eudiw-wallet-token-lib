package se.digg.wallet.datatypes.mdl.data;

import lombok.AllArgsConstructor;
import lombok.Getter;

@Getter
@AllArgsConstructor
public enum MdlDocType {
  mDL(""),
  EUDI_WALLET_PID("eu.europa.ec.eudi.pid.1");

  private final String id;
}

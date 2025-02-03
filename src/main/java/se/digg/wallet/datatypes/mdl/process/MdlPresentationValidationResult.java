package se.digg.wallet.datatypes.mdl.process;

import lombok.Data;
import lombok.EqualsAndHashCode;
import lombok.NoArgsConstructor;

@EqualsAndHashCode(callSuper = true)
@Data
@NoArgsConstructor
public class MdlPresentationValidationResult extends MdlIssuerSignedValidationResult {
  String docType;
  int status;
  String version;
}

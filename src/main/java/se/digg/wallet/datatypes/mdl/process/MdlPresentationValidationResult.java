package se.digg.wallet.datatypes.mdl.process;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;
import se.digg.wallet.datatypes.common.TokenValidationResult;
import se.digg.wallet.datatypes.mdl.data.IssuerSigned;
import se.digg.wallet.datatypes.mdl.data.IssuerSignedItem;
import se.digg.wallet.datatypes.mdl.data.MobileSecurityObject;

import java.util.List;

@Data
@AllArgsConstructor
@NoArgsConstructor
public class MdlPresentationValidationResult extends MdlIssuerSignedValidationResult {

  private List<IssuerSignedItem> disclosedItems;
  private MobileSecurityObject mso;
}

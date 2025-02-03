package se.digg.wallet.datatypes.mdl.data;

import lombok.Data;
import lombok.EqualsAndHashCode;
import lombok.NoArgsConstructor;
import se.digg.wallet.datatypes.common.PresentationValidationInput;

@EqualsAndHashCode(callSuper = true)
@Data
@NoArgsConstructor
public class MdlPresentationValidationInput extends PresentationValidationInput {

  private MdlPresentationInput mdlPresentationInput;

}

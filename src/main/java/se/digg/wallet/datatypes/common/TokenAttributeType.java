package se.digg.wallet.datatypes.common;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@AllArgsConstructor
@NoArgsConstructor
public class TokenAttributeType {

  private String nameSpace;
  private String attributeName;

  public TokenAttributeType(String attributeName) {
    this.attributeName = attributeName;
    this.nameSpace = null;
  }
}

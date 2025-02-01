package se.digg.wallet.datatypes.common;

import lombok.Getter;
import lombok.NoArgsConstructor;

import java.util.List;

@Getter
@NoArgsConstructor
public class PresentationInput<T extends Object> {

  protected byte[] token;
  protected String nonce;
  protected TokenSigningAlgorithm algorithm;
  protected List<TrustedKey> trustedKeys;
  protected T disclosures;

}

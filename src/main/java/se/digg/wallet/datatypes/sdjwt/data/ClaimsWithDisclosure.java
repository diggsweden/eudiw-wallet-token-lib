// SPDX-FileCopyrightText: 2024 Digg - Agency for Digital Government
//
// SPDX-License-Identifier: EUPL-1.2

package se.digg.wallet.datatypes.sdjwt.data;

import java.security.NoSuchAlgorithmException;
import java.util.*;
import lombok.Getter;
import se.digg.wallet.datatypes.common.TokenDigestAlgorithm;
import se.digg.wallet.datatypes.sdjwt.JSONUtils;

/**
 * This class represents all claims on one level (typically the base level). But any claim expressed here may declare a substructure.
 * Such substructures are provided in the Map named claimsWithDisclosure, which is cascading this class.
 * <p>
 *   Discloseable members at this level are provided in the disclosures list. These entries will form the content of the "_sd" Array.
 * </p>
 * <p>
 *   The arrayEntryMap holds a map of listed hash values that is to be serialized to JSON to reveal the discloseable members of each value array.
 * </p>
 *
 */
@Getter
public class ClaimsWithDisclosure {

  private String hashAlgo;

  /** This is a list of all disclosure items (List and Map entries) */
  private List<Disclosure> disclosures;

  /**
   * Claims on this level that has a list of values, where each value is either a value object or a selectable disclosure reference.
   * Eg:
   * <code>
   *   "nationalities": [
   *         "NO",
   *        {
   *          "...": "pFndjkZ_VCzmyTa6UjlZo3dh-ko8aIKQc9DlGzhaVYo"
   *        },
   *        {
   *          "...": "7Cf6JkPudry3lcbwHgeZ8khAv1U1OSlerP0VkBJrWZ0"
   *        }
   * </code>
   */
  private Map<String, List<Object>> arrayEntryMap;

  /** Any open claims that are not subject to selectable disclosure  */
  private Map<String, Object> openClaims;

  /**
   * Any members here are only included in case there is a sublevel of discloseable items.
   * This could be the case, for example, if a claim "Address"
   * has a substructure of individual subclaims each supporting selectable disclosure.
   */
  private Map<String, ClaimsWithDisclosure> claimsWithDisclosure;

  public static ClaimsWithDisclosure parse(
    Map<String, Object> claimsMap,
    List<Disclosure> disclosureList,
    TokenDigestAlgorithm sdAlg
  ) throws NoSuchAlgorithmException {
    ClaimsWithDisclosureBuilder cwdBuilder = ClaimsWithDisclosure.builder(
      sdAlg
    );
    List<String> sd = (List<String>) claimsMap.get("_sd");
    if (sd != null) {
      // There are disclosures at this level. Add them to this level
      for (Disclosure disc : disclosureList) {
        String hashString = JSONUtils.disclosureHashString(disc, sdAlg.getSdJwtName());
        if (sd.contains(hashString)) {
          cwdBuilder.disclosure(disc);
        }
      }
      Map<String, Object> filteredMap = new HashMap<>(claimsMap);
      filteredMap.remove("_sd");
      for (Map.Entry<String, Object> entry : filteredMap.entrySet()) {
        if (entry.getValue() instanceof Map) {
          Map<String, Object> subMap = (Map<String, Object>) entry.getValue();
          if (subMap.containsKey("_sd")) {
            ClaimsWithDisclosure subCwd = parse(subMap, disclosureList, sdAlg);
            cwdBuilder.claimsWithDisclosure(entry.getKey(), subCwd);
          } else {
            subMap
              .entrySet()
              .stream()
              .forEach(
                subEntry ->
                  cwdBuilder.openClaim(subEntry.getKey(), subEntry.getValue())
              );
          }
        }
        if (entry.getValue() instanceof List<?>) {
          List<Object> valueList = new ArrayList<>();
          for (Object item : (List<?>) entry.getValue()) {
            cwdBuilder.arrayEntry(entry.getKey(), item);
          }
          cwdBuilder.arrayEntry(entry.getKey(), valueList);
        } else {
          cwdBuilder.openClaim(entry.getKey(), entry.getValue());
        }
      }
    }
    return cwdBuilder.build();
  }

  public List<Disclosure> getAllDisclosures() {
    List<Disclosure> allDiscosures = new ArrayList<>(disclosures);
    if (claimsWithDisclosure != null) {
      allDiscosures.addAll(
        claimsWithDisclosure
          .values()
          .stream()
          .map(ClaimsWithDisclosure::getAllDisclosures)
          .flatMap(List::stream)
          .toList()
      );
    }
    return allDiscosures;
  }

  /**
   * Get all claims that need to be present in addition to the _sd selectably discolable claims and values
   * @return claims to include in the issuer signed jwt with selectable disclosure
   */
  public Map<String, Object> getAllSupportingClaims()
    throws NoSuchAlgorithmException {
    Map<String, Object> allSupportingClaims = new HashMap<>(openClaims);
    List<String> sdHashList = new ArrayList<>();
    for (Disclosure disclosure : getDisclosures()) {
      sdHashList.add(
        JSONUtils.base64URLString(
          JSONUtils.disclosureHash(disclosure, hashAlgo)
        )
      );
    }
    if (!sdHashList.isEmpty()) {
      allSupportingClaims.put("_sd", sdHashList);
    }

    allSupportingClaims.putAll(arrayEntryMap);
    if (claimsWithDisclosure != null) {
      claimsWithDisclosure.forEach((key, value) -> {
        try {
          allSupportingClaims.put(key, value.getAllSupportingClaims());
        } catch (NoSuchAlgorithmException e) {
          throw new RuntimeException(e);
        }
      });
    }
    return allSupportingClaims;
  }

  public static ClaimsWithDisclosureBuilder builder(TokenDigestAlgorithm hashAlgo) {
    return new ClaimsWithDisclosureBuilder(hashAlgo);
  }

  public static class ClaimsWithDisclosureBuilder {

    private ClaimsWithDisclosure claimsWithDisclosure;

    public ClaimsWithDisclosureBuilder(TokenDigestAlgorithm hashAlgo) {
      this.claimsWithDisclosure = new ClaimsWithDisclosure();
      this.claimsWithDisclosure.hashAlgo = hashAlgo.getSdJwtName();
      this.claimsWithDisclosure.disclosures = new ArrayList<>();
      this.claimsWithDisclosure.arrayEntryMap = new HashMap<>();
      this.claimsWithDisclosure.openClaims = new HashMap<>();
      this.claimsWithDisclosure.claimsWithDisclosure = new HashMap<>();
    }

    public ClaimsWithDisclosureBuilder disclosure(Disclosure disclosures) {
      this.claimsWithDisclosure.disclosures.add(disclosures);
      return this;
    }

    public ClaimsWithDisclosureBuilder arrayEntry(
      String claimName,
      Object valueOrDisclosure
    ) throws NoSuchAlgorithmException {
      List<Object> valueList =
        this.claimsWithDisclosure.arrayEntryMap.computeIfAbsent(
            claimName,
            s -> new ArrayList<>()
          );
      if (valueOrDisclosure instanceof Disclosure disclosure) {
        Map<String, String> disclosureRefValue = Collections.singletonMap(
          "...",
          JSONUtils.base64URLString(
            JSONUtils.disclosureHash(disclosure, claimsWithDisclosure.hashAlgo)
          )
        );
        valueList.add(disclosureRefValue);
        this.claimsWithDisclosure.disclosures.add(disclosure);
      } else {
        valueList.add(valueOrDisclosure);
      }
      return this;
    }

    public ClaimsWithDisclosureBuilder openClaim(String key, Object value) {
      this.claimsWithDisclosure.openClaims.put(key, value);
      return this;
    }

    public ClaimsWithDisclosureBuilder claimsWithDisclosure(
      String key,
      ClaimsWithDisclosure value
    ) {
      this.claimsWithDisclosure.claimsWithDisclosure.put(key, value);
      return this;
    }

    public ClaimsWithDisclosure build() {
      return claimsWithDisclosure;
    }
  }
}

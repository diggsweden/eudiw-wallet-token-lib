// SPDX-FileCopyrightText: 2024 Digg - Agency for Digital Government
//
// SPDX-License-Identifier: EUPL-1.2

package se.digg.wallet.datatypes.sdjwt.data;

import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import lombok.Getter;
import se.digg.wallet.datatypes.common.TokenDigestAlgorithm;
import se.digg.wallet.datatypes.common.Utils;
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
   * Any members here are only included in case there is a sublevel of disclosable items.
   * This could be the case, for example, if a claim "Address"
   * has a substructure of individual subclaims each supporting selectable disclosure.
   */
  private Map<String, ClaimsWithDisclosure> claimsWithDisclosure;

  /**
   * Parses a map of claims into an object that maps claims to their corresponding disclosures
   * using a provided list of disclosures and a specific token digest algorithm.
   *
   * @param claimsMap a map containing claim keys and their respective values, including potentially
   *                  nested claims and disclosures.
   * @param disclosureList a list of disclosures used for associating claim entries within the map.
   * @param sdAlg the token digest algorithm used for generating or validating hash strings of disclosures.
   * @return an instance of ClaimsWithDisclosure containing processed claims and their associated disclosures.
   * @throws NoSuchAlgorithmException if the token digest algorithm provided is not supported.
   * @throws IllegalArgumentException if the `_sd` parameter in the claims map is malformed.
   */
  public static ClaimsWithDisclosure parse(
    Map<String, Object> claimsMap,
    List<Disclosure> disclosureList,
    TokenDigestAlgorithm sdAlg
  ) throws NoSuchAlgorithmException {
    ClaimsWithDisclosureBuilder cwdBuilder = builder(sdAlg);
    if (claimsMap.get("_sd") != null) {
      if (claimsMap.get("_sd") instanceof List<?> sd) {
        // There are disclosures at this level. Add them to this level
        for (Disclosure disc : disclosureList) {
          String hashString = JSONUtils.disclosureHashString(
            disc,
            sdAlg.getSdJwtName()
          );
          if (sd.contains(hashString)) {
            cwdBuilder.disclosure(disc);
          }
        }
        Map<String, Object> filteredMap = new HashMap<>(claimsMap);
        filteredMap.remove("_sd");
        for (Map.Entry<String, Object> entry : filteredMap.entrySet()) {
          if (entry.getValue() instanceof Map<?, ?>) {
            Map<String, Object> subMap = Utils.ensureStringObjectMap(
              entry.getValue()
            );
            if (subMap.containsKey("_sd")) {
              ClaimsWithDisclosure subCwd = parse(
                subMap,
                disclosureList,
                sdAlg
              );
              cwdBuilder.claimsWithDisclosure(entry.getKey(), subCwd);
            } else {
              subMap.forEach(cwdBuilder::openClaim);
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
      } else {
        throw new IllegalArgumentException("Malformed _sd parameter");
      }
    }
    return cwdBuilder.build();
  }

  /**
   * Retrieves all disclosures associated with the current object, including disclosures
   * stored in the list and any nested disclosures within claims.
   *
   * @return a list of all disclosures, combining both direct and nested disclosures.
   */
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
   *
   * @return claims to include in the issuer signed jwt with selectable disclosure
   * @throws NoSuchAlgorithmException if an unsupported algorithm is encountered while computing hashes.
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

  /**
   * Creates a new instance of ClaimsWithDisclosureBuilder using the specified token digest algorithm.
   *
   * @param hashAlgo the token digest algorithm to be used for handling claim disclosures.
   * @return a new instance of ClaimsWithDisclosureBuilder initialized with the provided token digest algorithm.
   */
  public static ClaimsWithDisclosureBuilder builder(
    TokenDigestAlgorithm hashAlgo
  ) {
    return new ClaimsWithDisclosureBuilder(hashAlgo);
  }

  /**
   * A builder class for constructing an instance of ClaimsWithDisclosure.
   * Provides methods for adding claims, disclosures, and other related data
   * to create a finalized ClaimsWithDisclosure object.
   */
  public static class ClaimsWithDisclosureBuilder {

    /**
     * The object being built by this builder
     */
    private final ClaimsWithDisclosure claimsWithDisclosure;

    /**
     * Constructs a new ClaimsWithDisclosureBuilder instance.
     * Initializes an empty ClaimsWithDisclosure object and sets up
     * the hashing algorithm for disclosures based on the provided TokenDigestAlgorithm.
     *
     * @param hashAlgo the TokenDigestAlgorithm used for defining the hash function for disclosures.
     */
    public ClaimsWithDisclosureBuilder(TokenDigestAlgorithm hashAlgo) {
      this.claimsWithDisclosure = new ClaimsWithDisclosure();
      this.claimsWithDisclosure.hashAlgo = hashAlgo.getSdJwtName();
      this.claimsWithDisclosure.disclosures = new ArrayList<>();
      this.claimsWithDisclosure.arrayEntryMap = new HashMap<>();
      this.claimsWithDisclosure.openClaims = new HashMap<>();
      this.claimsWithDisclosure.claimsWithDisclosure = new HashMap<>();
    }

    /**
     * Adds a disclosure object to the list of disclosures in the ClaimsWithDisclosure being built.
     *
     * @param disclosures the {@link Disclosure} object containing disclosure data to be added
     * @return the current instance of {@link ClaimsWithDisclosureBuilder} for method chaining
     */
    public ClaimsWithDisclosureBuilder disclosure(Disclosure disclosures) {
      this.claimsWithDisclosure.disclosures.add(disclosures);
      return this;
    }

    /**
     * Adds an entry to the specified claim as an array. If the value provided
     * is a {@link Disclosure} object, it will be hashed using the defined
     * hashing algorithm and stored as a reference. Otherwise, the value is
     * directly added to the list for the claim.
     *
     * @param claimName the name of the claim to which the value or disclosure will be added
     * @param valueOrDisclosure the value or {@link Disclosure} object to be added to the claim's array
     * @return the current instance of {@link ClaimsWithDisclosureBuilder} for method chaining
     * @throws NoSuchAlgorithmException if the hashing algorithm for the disclosure is not supported
     */
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

    /**
     * Adds an entry to the open claims within the ClaimsWithDisclosure being built.
     * The specified key-value pair is stored in the open claims map, meaning that this claim
     * is presented in clear text and will be available always without any disclosure data.
     *
     * @param key the key for the open claim to be added
     * @param value the value associated with the specified key for the open claim
     * @return the current instance of {@link ClaimsWithDisclosureBuilder} for method chaining
     */
    public ClaimsWithDisclosureBuilder openClaim(String key, Object value) {
      this.claimsWithDisclosure.openClaims.put(key, value);
      return this;
    }

    /**
     * Adds a sublevel ClaimsWithDisclosure structure to this ClaimsWithDisclosure object under a claim name as key.
     *
     * @param key the claim name to associate with the ClaimsWithDisclosure value
     * @param value the ClaimsWithDisclosure value to be added to the map
     * @return the current instance of ClaimsWithDisclosureBuilder for method chaining
     */
    public ClaimsWithDisclosureBuilder claimsWithDisclosure(
      String key,
      ClaimsWithDisclosure value
    ) {
      this.claimsWithDisclosure.claimsWithDisclosure.put(key, value);
      return this;
    }

    /**
     * Builds and returns the constructed ClaimsWithDisclosure object.
     *
     * @return the constructed instance of {@link ClaimsWithDisclosure}
     */
    public ClaimsWithDisclosure build() {
      return claimsWithDisclosure;
    }
  }
}

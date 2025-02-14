// SPDX-FileCopyrightText: 2025 Digg - Agency for Digital Government
//
// SPDX-License-Identifier: EUPL-1.2

package se.digg.wallet.datatypes.common;

import java.util.List;
import java.util.Map;

/**
 * Utility class containing helper methods for various operations.
 */
public class Utils {

  /**
   * Ensures that the provided object is a Map with String keys and returns it as a {@code Map&ltString, Object>}.
   * If the input is not a Map with String keys, an IllegalArgumentException is thrown.
   *
   * @param value the object to validate and cast
   * @return the validated and cast {@code Map&ltString, Object>}
   * @throws IllegalArgumentException if the provided object is not a Map or if the Map's keys are not Strings
   */
  @SuppressWarnings("unchecked")
  public static Map<String, Object> ensureStringObjectMap(Object value) {
    if (
      value instanceof Map<?, ?> map &&
      map.keySet().stream().allMatch(key -> key instanceof String)
    ) {
      return (Map<String, Object>) map;
    }
    throw new IllegalArgumentException(
      "Invalid Map structure: keys must be Strings"
    );
  }

  /**
   * Ensures that the provided object is a List containing only String elements
   * and returns it as a {@code List<String>}. If the input object is not a List
   * with all String elements, an IllegalArgumentException is thrown.
   *
   * @param value the object to validate and cast
   * @return the validated and cast {@code List<String>}
   * @throws IllegalArgumentException if the provided object is not a List or if the List's
   *         elements are not all Strings
   */
  @SuppressWarnings("unchecked")
  public static List<String> ensureStringList(Object value) {
    if (
      value instanceof List<?> list &&
      list.stream().allMatch(item -> item instanceof String)
    ) {
      return (List<String>) list;
    }
    throw new IllegalArgumentException(
      "Invalid List structure: items must be Strings"
    );
  }
}

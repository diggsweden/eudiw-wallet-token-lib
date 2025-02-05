// SPDX-FileCopyrightText: 2024 Digg - Agency for Digital Government
//
// SPDX-License-Identifier: EUPL-1.2

package se.digg.wallet.datatypes.common;

import java.time.Duration;
import java.time.Instant;
import java.time.LocalDate;
import java.time.ZoneId;
import java.util.List;

public class TestData {

  public static final List<TokenAttribute> defaultPidUserAttributes = List.of(
    TokenAttribute.builder()
      .type(new TokenAttributeType(
        TokenAttributeNameSpace.EUDI_WALLET_PID.getId(),
        "issuance_date"))
      .value(LocalDate.ofInstant(Instant.now(), ZoneId.systemDefault()))
      .build(),
    TokenAttribute.builder()
      .type(new TokenAttributeType(
        TokenAttributeNameSpace.EUDI_WALLET_PID.getId(),
        "issuing_country"))
      .value("SE")
      .build(),
    TokenAttribute.builder()
      .type(new TokenAttributeType(
        TokenAttributeNameSpace.EUDI_WALLET_PID.getId(),
        "given_name"))
      .value("Johnny")
      .build(),
    TokenAttribute.builder()
      .type(new TokenAttributeType(
        TokenAttributeNameSpace.EUDI_WALLET_PID.getId(),
        "age_over_18"))
      .value(true)
      .build(),
    TokenAttribute.builder()
      .type(new TokenAttributeType(
        TokenAttributeNameSpace.EUDI_WALLET_PID.getId(),
        "birth_date"))
      .value(LocalDate.of(1986, 02, 21))
      .build(),
    TokenAttribute.builder()
      .type(new TokenAttributeType(
        TokenAttributeNameSpace.EUDI_WALLET_PID.getId(),
        "expiry_date"))
      .value(
        LocalDate.ofInstant(
          Instant.now().plus(Duration.ofDays(1)),
          ZoneId.systemDefault()
        )
      )
      .build(),
    TokenAttribute.builder()
      .type(new TokenAttributeType(
        TokenAttributeNameSpace.EUDI_WALLET_PID.getId(),
        "family_name"
      ))
      .value("Thuland")
      .build(),
    TokenAttribute.builder()
      .type(new TokenAttributeType(
        TokenAttributeNameSpace.EUDI_WALLET_PID.getId(),
        "issuing_authority"))
      .value("Test PID issuer")
      .build()
  );

  public static final String SD_TWT_RFC_REF =
    "eyJhbGciOiAiRVMyNTYiLCAidHlwIjogImRjK3NkLWp3dCIsICJraWQiOiAiZG9jLXNpZ25lci0wNS0yNS0yMDIyIn0.eyJfc2QiOiBbIjA5dktySk1PbHlUV00wc2pwdV9wZE9CVkJRMk0xeTNLaHBINTE1blhrcFkiLCAiMnJzakdiYUMwa3k4bVQwcEpyUGlvV1RxMF9kYXcxc1g3NnBvVWxnQ3diSSIsICJFa084ZGhXMGRIRUpidlVIbEVfVkNldUM5dVJFTE9pZUxaaGg3WGJVVHRBIiwgIklsRHpJS2VpWmREd3BxcEs2WmZieXBoRnZ6NUZnbldhLXNPNndxUVhDaXciLCAiSnpZakg0c3ZsaUgwUjNQeUVNZmVadTZKdDY5dTVxZWhabzdGN0VQWWxTRSIsICJQb3JGYnBLdVZ1Nnh5bUphZ3ZrRnNGWEFiUm9jMkpHbEFVQTJCQTRvN2NJIiwgIlRHZjRvTGJnd2Q1SlFhSHlLVlFaVTlVZEdFMHc1cnREc3JaemZVYW9tTG8iLCAiamRyVEU4WWNiWTRFaWZ1Z2loaUFlX0JQZWt4SlFaSUNlaVVRd1k5UXF4SSIsICJqc3U5eVZ1bHdRUWxoRmxNXzNKbHpNYVNGemdsaFFHMERwZmF5UXdMVUs0Il0sICJpc3MiOiAiaHR0cHM6Ly9leGFtcGxlLmNvbS9pc3N1ZXIiLCAiaWF0IjogMTY4MzAwMDAwMCwgImV4cCI6IDE4ODMwMDAwMDAsICJ2Y3QiOiAiaHR0cHM6Ly9jcmVkZW50aWFscy5leGFtcGxlLmNvbS9pZGVudGl0eV9jcmVkZW50aWFsIiwgIl9zZF9hbGciOiAic2hhLTI1NiIsICJjbmYiOiB7Imp3ayI6IHsia3R5IjogIkVDIiwgImNydiI6ICJQLTI1NiIsICJ4IjogIlRDQUVSMTladnUzT0hGNGo0VzR2ZlNWb0hJUDFJTGlsRGxzN3ZDZUdlbWMiLCAieSI6ICJaZGppV1diWk1RR0hWV0tWUTRoYlNJaXJzVmZ1ZWNDRTZ0NGpUOUYySFpRIn19fQ.2CyX0v3AAFG9y-A_Z46uz9hHsNbr0yWTbDQaajLCrsxo-JxVh4a9dAMFVYZ8GFG2wgj2jKnA42wSgv7xVM64PA~WyJsa2x4RjVqTVlsR1RQVW92TU5JdkNBIiwgImlzX292ZXJfNjUiLCB0cnVlXQ~WyJRZ19PNjR6cUF4ZTQxMmExMDhpcm9BIiwgImFkZHJlc3MiLCB7InN0cmVldF9hZGRyZXNzIjogIjEyMyBNYWluIFN0IiwgImxvY2FsaXR5IjogIkFueXRvd24iLCAicmVnaW9uIjogIkFueXN0YXRlIiwgImNvdW50cnkiOiAiVVMifV0~eyJhbGciOiAiRVMyNTYiLCAidHlwIjogImtiK2p3dCJ9.eyJub25jZSI6ICIxMjM0NTY3ODkwIiwgImF1ZCI6ICJodHRwczovL2V4YW1wbGUuY29tL3ZlcmlmaWVyIiwgImlhdCI6IDE3MzMyMzAxNDAsICJzZF9oYXNoIjogIkhWVjBCcG5FTHlHTnRVVFlCLU5nWHhmN2pvTjZBekprYVdEOUVkNVo1VjgifQ.FJLPPlBB2wOWEYLLtwd7WYlaTpIz0ALlRuskPi0fSYFDEn25gGkXSSJsQxjhryxqN4aLbwMRRfcvDdk1A_eLHQ";
}

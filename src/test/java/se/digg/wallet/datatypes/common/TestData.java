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
      .type(
        new TokenAttributeType(
          TokenAttributeNameSpace.EUDI_WALLET_PID.getId(),
          "issuance_date"
        )
      )
      .value(LocalDate.ofInstant(Instant.now(), ZoneId.systemDefault()))
      .build(),
    TokenAttribute.builder()
      .type(
        new TokenAttributeType(
          TokenAttributeNameSpace.EUDI_WALLET_PID.getId(),
          "issuing_country"
        )
      )
      .value("SE")
      .build(),
    TokenAttribute.builder()
      .type(
        new TokenAttributeType(
          TokenAttributeNameSpace.EUDI_WALLET_PID.getId(),
          "given_name"
        )
      )
      .value("Johnny")
      .build(),
    TokenAttribute.builder()
      .type(
        new TokenAttributeType(
          TokenAttributeNameSpace.EUDI_WALLET_PID.getId(),
          "age_over_18"
        )
      )
      .value(true)
      .build(),
    TokenAttribute.builder()
      .type(
        new TokenAttributeType(
          TokenAttributeNameSpace.EUDI_WALLET_PID.getId(),
          "birth_date"
        )
      )
      .value(LocalDate.of(1986, 02, 21))
      .build(),
    TokenAttribute.builder()
      .type(
        new TokenAttributeType(
          TokenAttributeNameSpace.EUDI_WALLET_PID.getId(),
          "expiry_date"
        )
      )
      .value(
        LocalDate.ofInstant(
          Instant.now().plus(Duration.ofDays(1)),
          ZoneId.systemDefault()
        )
      )
      .build(),
    TokenAttribute.builder()
      .type(
        new TokenAttributeType(
          TokenAttributeNameSpace.EUDI_WALLET_PID.getId(),
          "family_name"
        )
      )
      .value("Thuland")
      .build(),
    TokenAttribute.builder()
      .type(
        new TokenAttributeType(
          TokenAttributeNameSpace.EUDI_WALLET_PID.getId(),
          "issuing_authority"
        )
      )
      .value("Test PID issuer")
      .build()
  );

  public static final String SD_TWT_RFC_REF =
    "eyJhbGciOiAiRVMyNTYiLCAidHlwIjogImRjK3NkLWp3dCIsICJraWQiOiAiZG9jLXNpZ25lci0wNS0yNS0yMDIyIn0.eyJfc2QiOiBbIjA5dktySk1PbHlUV00wc2pwdV9wZE9CVkJRMk0xeTNLaHBINTE1blhrcFkiLCAiMnJzakdiYUMwa3k4bVQwcEpyUGlvV1RxMF9kYXcxc1g3NnBvVWxnQ3diSSIsICJFa084ZGhXMGRIRUpidlVIbEVfVkNldUM5dVJFTE9pZUxaaGg3WGJVVHRBIiwgIklsRHpJS2VpWmREd3BxcEs2WmZieXBoRnZ6NUZnbldhLXNPNndxUVhDaXciLCAiSnpZakg0c3ZsaUgwUjNQeUVNZmVadTZKdDY5dTVxZWhabzdGN0VQWWxTRSIsICJQb3JGYnBLdVZ1Nnh5bUphZ3ZrRnNGWEFiUm9jMkpHbEFVQTJCQTRvN2NJIiwgIlRHZjRvTGJnd2Q1SlFhSHlLVlFaVTlVZEdFMHc1cnREc3JaemZVYW9tTG8iLCAiamRyVEU4WWNiWTRFaWZ1Z2loaUFlX0JQZWt4SlFaSUNlaVVRd1k5UXF4SSIsICJqc3U5eVZ1bHdRUWxoRmxNXzNKbHpNYVNGemdsaFFHMERwZmF5UXdMVUs0Il0sICJpc3MiOiAiaHR0cHM6Ly9leGFtcGxlLmNvbS9pc3N1ZXIiLCAiaWF0IjogMTY4MzAwMDAwMCwgImV4cCI6IDE4ODMwMDAwMDAsICJ2Y3QiOiAiaHR0cHM6Ly9jcmVkZW50aWFscy5leGFtcGxlLmNvbS9pZGVudGl0eV9jcmVkZW50aWFsIiwgIl9zZF9hbGciOiAic2hhLTI1NiIsICJjbmYiOiB7Imp3ayI6IHsia3R5IjogIkVDIiwgImNydiI6ICJQLTI1NiIsICJ4IjogIlRDQUVSMTladnUzT0hGNGo0VzR2ZlNWb0hJUDFJTGlsRGxzN3ZDZUdlbWMiLCAieSI6ICJaZGppV1diWk1RR0hWV0tWUTRoYlNJaXJzVmZ1ZWNDRTZ0NGpUOUYySFpRIn19fQ.2CyX0v3AAFG9y-A_Z46uz9hHsNbr0yWTbDQaajLCrsxo-JxVh4a9dAMFVYZ8GFG2wgj2jKnA42wSgv7xVM64PA~WyJsa2x4RjVqTVlsR1RQVW92TU5JdkNBIiwgImlzX292ZXJfNjUiLCB0cnVlXQ~WyJRZ19PNjR6cUF4ZTQxMmExMDhpcm9BIiwgImFkZHJlc3MiLCB7InN0cmVldF9hZGRyZXNzIjogIjEyMyBNYWluIFN0IiwgImxvY2FsaXR5IjogIkFueXRvd24iLCAicmVnaW9uIjogIkFueXN0YXRlIiwgImNvdW50cnkiOiAiVVMifV0~eyJhbGciOiAiRVMyNTYiLCAidHlwIjogImtiK2p3dCJ9.eyJub25jZSI6ICIxMjM0NTY3ODkwIiwgImF1ZCI6ICJodHRwczovL2V4YW1wbGUuY29tL3ZlcmlmaWVyIiwgImlhdCI6IDE3MzMyMzAxNDAsICJzZF9oYXNoIjogIkhWVjBCcG5FTHlHTnRVVFlCLU5nWHhmN2pvTjZBekprYVdEOUVkNVo1VjgifQ.FJLPPlBB2wOWEYLLtwd7WYlaTpIz0ALlRuskPi0fSYFDEn25gGkXSSJsQxjhryxqN4aLbwMRRfcvDdk1A_eLHQ";

  public static final String SD_JWT_EUDI_REF_01 =
    "eyJhbGciOiAiRVMyNTYiLCAidHlwIjogInZjK3NkLWp3dCIsICJ4NWMiOiBbIk1JSURBRENDQW9hZ0F3SUJBZ0lVR2F6SzNndW5wMkFrVnpvODI0a0JHNGhWKzFnd0NnWUlLb1pJemowRUF3SXdYREVlTUJ3R0ExVUVBd3dWVUVsRUlFbHpjM1ZsY2lCRFFTQXRJRlZVSURBeE1TMHdLd1lEVlFRS0RDUkZWVVJKSUZkaGJHeGxkQ0JTWldabGNtVnVZMlVnU1cxd2JHVnRaVzUwWVhScGIyNHhDekFKQmdOVkJBWVRBbFZVTUI0WERUSTFNREV4TkRFeU5UY3lNMW9YRFRJMk1EUXdPVEV5TlRjeU1sb3dVekVWTUJNR0ExVUVBd3dNVUVsRUlFUlRJQzBnTURBek1TMHdLd1lEVlFRS0RDUkZWVVJKSUZkaGJHeGxkQ0JTWldabGNtVnVZMlVnU1cxd2JHVnRaVzUwWVhScGIyNHhDekFKQmdOVkJBWVRBbFZVTUZrd0V3WUhLb1pJemowQ0FRWUlLb1pJemowREFRY0RRZ0FFQXk1Mlo0ZG9RNk1DZEF1RzFVOWZGRmZLdmxobUdibXRTVlhkRjdCTnl2a3RtUWJjaDU4aFpPZkl0SDhqMjl3Y1UzT0dmM25ORW8xRkc4bzF2T29yYTZPQ0FTMHdnZ0VwTUI4R0ExVWRJd1FZTUJhQUZMTnN1SkVYSE5la0dtWXhoMExoaThCQXpKVWJNQnNHQTFVZEVRUVVNQktDRUdsemMzVmxjaTVsZFdScGR5NWtaWFl3RmdZRFZSMGxBUUgvQkF3d0NnWUlLNEVDQWdBQUFRSXdRd1lEVlIwZkJEd3dPakE0b0RhZ05JWXlhSFIwY0hNNkx5OXdjbVZ3Y205a0xuQnJhUzVsZFdScGR5NWtaWFl2WTNKc0wzQnBaRjlEUVY5VlZGOHdNUzVqY213d0hRWURWUjBPQkJZRUZIN1FJR1FTYkxncURTOFBkcTVVdS9JeVgzK0lNQTRHQTFVZER3RUIvd1FFQXdJSGdEQmRCZ05WSFJJRVZqQlVobEpvZEhSd2N6b3ZMMmRwZEdoMVlpNWpiMjB2WlhVdFpHbG5hWFJoYkMxcFpHVnVkR2wwZVMxM1lXeHNaWFF2WVhKamFHbDBaV04wZFhKbExXRnVaQzF5WldabGNtVnVZMlV0Wm5KaGJXVjNiM0pyTUFvR0NDcUdTTTQ5QkFNQ0EyZ0FNR1VDTUZoNEUrU2JvZ3hGRHphbFF0M3RWV1drY3F4NmhjSW1VUTZVVndMZUJXUFJvS2dweUNueUdwK3lMSERXckd2b09RSXhBTzE1NUFIK1QzTWcxNE9jNlFuYzZIdDZvK1l1SU44NnZvTzZHa3djb25Ic3JjQlNqNVR3SmNxTkI1cXRmN0kxOXc9PSJdfQ.eyJfc2QiOiBbIjB2aC1ZcnFET0JZTDNsa0JIVndNT080QjlJdTB2RE85bHdpWmk4RnRqQjQiLCAiSzlwbmU1TGN4OFhiMGF6dFJLdGhPRXdrTm5peWstc1JUX3JMdmFSbHNIWSIsICJVTjFkVzNfMlVxXzlLOEcwa1hIMDBIc3d1OFR4Ynk5czU2RTVTemZWaFpnIiwgIlhpSkl4eWdBVjl4SG9uRXNPcE5SMnFzTzU1d0dFejdDN0xQWkxsQnhjRGMiLCAiamM4UkhQMVJMZDhaWVNoV1FlSDhXanFSOHR0MjRwNDkyeXZuV3NYckc5TSIsICJvd3QzZzZmeUpSRFItVUM5bEJwaXBjOV9xaE9VLXpEeEdQazh1RjdnTjJjIl0sICJpc3MiOiAiaHR0cHM6Ly9pc3N1ZXIuZXVkaXcuZGV2IiwgImlhdCI6IDE3Mzg2MjcyMDAsICJleHAiOiAxNzQ2Mzk5NjAwLCAidmN0IjogInVybjpldS5ldXJvcGEuZWMuZXVkaTpwaWQ6MSIsICJzdGF0dXMiOiB7ImlkZW50aWZpZXJfbGlzdCI6IHsiaWQiOiAiNTAiLCAidXJpIjogImh0dHBzOi8vaXNzdWVyLmV1ZGl3LmRldi9pZGVudGlmaWVyX2xpc3QvRkMvZXUuZXVyb3BhLmVjLmV1ZGkucGlkLjEvODJkM2VhZmYtYzhjZS00MzI5LWE3OTUtYjdkOTE3ZjNlNWFiIn0sICJzdGF0dXNfbGlzdCI6IHsiaWR4IjogNTAsICJ1cmkiOiAiaHR0cHM6Ly9pc3N1ZXIuZXVkaXcuZGV2L3Rva2VuX3N0YXR1c19saXN0L0ZDL2V1LmV1cm9wYS5lYy5ldWRpLnBpZC4xLzgyZDNlYWZmLWM4Y2UtNDMyOS1hNzk1LWI3ZDkxN2YzZTVhYiJ9fSwgIl9zZF9hbGciOiAic2hhLTI1NiIsICJjbmYiOiB7Imp3ayI6IHsia3R5IjogIkVDIiwgImNydiI6ICJQLTI1NiIsICJ4IjogImVqOU1jeFFHZmNHS05MOVpEUG5lMW1QZXVMbDc5WmJGOHFPcEVrY3VxSmsiLCAieSI6ICJPNTM1Qzh4WTRqd1JUNk5UVWQySWRfNndld3ZYcmVPSjBTUVRfQ3VhTDFZIn19fQ.rB2awMzrgtdXJBQBNE_nUK610XQhR1K_GTG940w2jCyPSOP30rDaXUurMgcHJnVEZEYIglvFj9okvGjzdb7g2A~WyIxWm9mYzhwMVAwWVNVdVZ3MFNDTjl3IiwgImlzc3VpbmdfYXV0aG9yaXR5IiwgIlRlc3QgUElEIGlzc3VlciJd~WyJGZFJ6LUtwMDdwRTRQbmd2NzZhbmRnIiwgImJpcnRoZGF0ZSIsICIxOTgxLTAyLTA0Il0~WyJhQmRON3VCWjJVUDlROU03X2hKeDB3IiwgImZhbWlseV9uYW1lIiwgInVqIl0~WyJpUFdRX3pmTnNiTzZ1cEgzaHJqVmhnIiwgImlzc3VpbmdfY291bnRyeSIsICJGQyJd~eyJ0eXAiOiJrYitqd3QiLCJhbGciOiJFUzI1NiJ9.eyJzZF9oYXNoIjoiVElDb1Bkc1d4M1l5bzBDZ2lDaXJ0c1M5ai1jemRzQVVyRGdqUGhkd2dJdyIsImF1ZCI6InZlcmlmaWVyLWJhY2tlbmQuZXVkaXcuZGV2Iiwibm9uY2UiOiJlNzhlYzMxMy0wODZmLTRmNzItOWZhOC0yMTYyYWNkNzAwYjciLCJpYXQiOjE3Mzg5MTg5ODV9.NzaIEGMVyfbXGCFbyrzLTu21X3FjmEN192tbgSW9U4hzpU9I14ZBsID4kP8ExuGVcXYkIlNpGIg4PuXvKOpv5A";
  public static final String SD_JWT_EUDI_REF_01_NONCE =
    "e78ec313-086f-4f72-9fa8-2162acd700b7";
  public static final String SD_JWT_EUDI_REF_01_AUDIENCE =
    "verifier-backend.eudiw.dev";
}

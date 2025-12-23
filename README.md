# EUDIW Wallet Token Library

[![Tag](https://img.shields.io/github/v/tag/diggsweden/eudiw-wallet-token-lib?style=for-the-badge&color=green)](https://github.com/diggsweden/eudiw-wallet-token-lib/tags)

[![License: EUPL 1.2](https://img.shields.io/badge/License-European%20Union%20Public%20Licence%201.2-library?style=for-the-badge&&color=lightblue)](LICENSE)
[![REUSE](https://img.shields.io/badge/dynamic/json?url=https%3A%2F%2Fapi.reuse.software%2Fstatus%2Fgithub.com%2Fdiggsweden%2Feudiw-wallet-token-lib&query=status&style=for-the-badge&label=REUSE&color=lightblue)](https://api.reuse.software/info/github.com/diggsweden/eudiw-wallet-token-lib)

[![OpenSSF Scorecard](https://api.scorecard.dev/projects/github.com/diggsweden/eudiw-wallet-token-lib/badge?style=for-the-badge)](https://scorecard.dev/viewer/?uri=github.com/diggsweden/eudiw-wallet-token-lib)
[![OpenSSF Best Practice](https://img.shields.io/badge/dynamic/json?url=https%3A%2F%2Fbestpractices.coreinfrastructure.org%2Fprojects%2F10000000.json&query=%24.badge_level&style=for-the-badge&label=OpenSSF%20Best%20Practice&color=green)](https://www.bestpractices.dev/en/projects/100000)

A library supporting different token formats for EUDI wallet such as SD-JWT and mDL
s
## SD-JWT

The SD-JWT token format is based on the Selective Disclosure for JWTs (SD-JWT) specification developed by the IETF ([draft-ietf-oauth-selective-disclosure-jwt](https://datatracker.ietf.org/doc/html/draft-ietf-oauth-selective-disclosure-jwt)) as well as the SD-JWT-based Verifiable Credentials ([draft-ietf-oauth-sd-jwt-vc](https://datatracker.ietf.org/doc/html/draft-ietf-oauth-sd-jwt-vc-08)).

## mDL

The mDL token format are based on ISO/IEC 18013-5 and is using ISO/IEC 18013-7 for the presentation format to specify the means to bind the presentation to the wallet private key.

## Maven

Add this maven dependency to your project

```xml
<dependency>
    <groupId>se.digg.wallet</groupId>
    <artifactId>eudiw-wallet-token-lib</artifactId>
    <version>${wallet-token-lib.version}</version>
</dependency>
```

## Usage

This library supports the following main operations with SD_JWT and mDL tokens:

Operation | Token
---|---
**issue token**|Issues a token to a EUDI wallet, bound to the wallet public key and bundled with necessary selective disclosure data
**validate token** | Validates a token issued by the token issuer. This is the operation that typically is carried out by the wallet upon recipt of a token from the token issuer.
**present token** | Create a presentation of selectably discolsed data based on the issued token, bound to the wallet private key.
**validate presentation** | Validate a presentation and collect the discolsed token attributes

The sections below illustrate how this library is used to perform these operations.

### SD_JWT

The examples below can be found in [SdJwtImplementationExampleTests.java](src/test/java/se/digg/wallet/datatypes/examples/SdJwtImplementationExampleTests.java)

#### Issue token

```java
  byte[] issueSdJwt() throws Exception
  {
    SdJwtTokenInput tokenInput = SdJwtTokenInput.sdJwtINputBuilder()
        .algorithm(TokenSigningAlgorithm.ECDSA_256)
        .issuerCredential(issuerCredential)
        .walletPublicKey(walletPublicKey)
        .expirationDuration(Duration.ofHours(12))
        .verifiableCredentialType("eu.europa.ec.eudi.pid.1")
        .issuer("https://example.com/issuer")
        .attributes(List.of(
            TokenAttribute.builder()
                .type(new TokenAttributeType("given_name"))
                .value("John")
                .build(),
            TokenAttribute.builder()
                .type(new TokenAttributeType("family_name"))
                .value("Doe")
                .build()
        ))
        .build();
    SdJwtTokenIssuer tokenIssuer = new SdJwtTokenIssuer();
    return tokenIssuer.issueToken(tokenInput);
  }
```

#### Validate token

```java
  SdJwtTokenValidationResult validateSDJwtToken(byte[] sdJwtToken, List<TrustedKey> trustedKeys)
      throws Exception
  {
    SdJwtTokenValidator tokenValidator = new SdJwtTokenValidator();
    return tokenValidator.validateToken(
        sdJwtToken,
        trustedKeys);
  }
```

#### present token

```java
  byte[] presentSdJwtToken(byte[] token) throws Exception
  {
    SdJwtTokenPresenter tokenPresenter = new SdJwtTokenPresenter();

    SdJwtPresentationInput presentationInput = SdJwtPresentationInput.builder()
        .algorithm(TokenSigningAlgorithm.ECDSA_256)
        .token(token)
        .nonce("1234567890_nonce")
        .audience("https://example.com/aud")
        .disclosures(List.of("given_name", "family_name"))
        .build();
    return tokenPresenter.presentToken(presentationInput, walletKeyPair.toPrivateKey());
  }
```

#### Validate presentation

```java
  SdJwtTokenValidationResult validateSdJwtPresentation(byte[] sdJwtPresentation,
      List<TrustedKey> trustedKeys) throws Exception
  {
    SdJwtPresentationValidator sdJwtPresentationValidator = new SdJwtPresentationValidator();
    return sdJwtPresentationValidator.validatePresentation(
        sdJwtPresentation,
        SdJwtPresentationValidationInput.builder()
            .requestNonce("1234567890_nonce")
            .audience("https://example.com/aud")
            .build(),
        trustedKeys);
  }
```

### mDL

The examples below can be found in [MdlImplementationExampleTests.java](src/test/java/se/digg/wallet/datatypes/examples/MdlImplementationExampleTests.java)

#### Issue mDL token

```java
byte[] issueMdlToken() throws Exception
{
  TokenInput tokenInput = TokenInput.builder()
      .algorithm(TokenSigningAlgorithm.ECDSA_256)
      .issuerCredential(issuerCredential)
      .walletPublicKey(walletPublicKey)
      .expirationDuration(Duration.ofHours(12))
      .attributes(List.of(
          TokenAttribute.builder()
              .type(new TokenAttributeType(TokenAttributeNameSpace.EUDI_WALLET_PID.getId(),"given_name"))
              .value("John")
              .build(),
          TokenAttribute.builder()
              .type(new TokenAttributeType(TokenAttributeNameSpace.EUDI_WALLET_PID.getId(),"family_name"))
              .value("Doe")
              .build()
      ))
      .build();
  MdlTokenIssuer tokenIssuer = new MdlTokenIssuer();
  return tokenIssuer.issueToken(tokenInput);
}
```

#### Validate mDL token

```java
  MdlIssuerSignedValidationResult validateMdlToken(byte[] mdlToken, List<TrustedKey> trustedKeys)
    throws Exception
  {
    MdlIssuerSignedValidator tokenValidator = new MdlIssuerSignedValidator();
    return tokenValidator.validateToken(mdlToken, trustedKeys);
  }
```

#### Present mDL token

Default presentation using device signature to bind the token to the wallet private key.

```java
byte[] presentMdlToken(byte[] token) throws Exception
{
  MdlTokenPresenter tokenPresenter = new MdlTokenPresenter();

  MdlPresentationInput presentationInput = MdlPresentationInput.builder()
      .algorithm(TokenSigningAlgorithm.ECDSA_256)
      .token(token)
      .nonce("1234567890_nonce")
      .responseUri("https://example.com/aud")
      .clientId("https://example.com/client")
      .mdocGeneratedNonce("0987654321_walletNonce")
      .disclosures(Collections.singletonMap(TokenAttributeNameSpace.EUDI_WALLET_PID.getId(), 
          List.of("given_name", "family_name")))
      .build();
  return tokenPresenter.presentToken(presentationInput, walletKeyPair.toPrivateKey());
}
```

Optional extension to use MAC to bind the token to the wallet privte key

```java
byte[] presentMdlTokenWithMac(byte[] token) throws Exception
{
  MdlTokenPresenter tokenPresenter = new MdlTokenPresenter();

  MdlPresentationInput presentationInput = MdlPresentationInput.builder()
      .algorithm(TokenSigningAlgorithm.ECDSA_256)
      .token(token)
      .nonce("1234567890_nonce")
      .responseUri("https://example.com/aud")
      .clientId("https://example.com/client")
      .mdocGeneratedNonce("0987654321_walletNonce")
      .clientPublicKey(clientKeyPair.toPublicKey())
      .macDeviceAuthentication(true)
      .disclosures(Collections.singletonMap(TokenAttributeNameSpace.EUDI_WALLET_PID.getId(), 
          List.of("given_name", "family_name")))
      .build();
  return tokenPresenter.presentToken(presentationInput, walletKeyPair.toPrivateKey());
}
```

#### Validate mDL presentation

Default validation to validate presentations where device signature was used to prove possession of wallet private key.

```java
  MdlPresentationValidationResult validateMdlPresentation(byte[] sdJwtPresentation,
      List<TrustedKey> trustedKeys) throws Exception
  {
    MdlPresentationValidator sdJwtPresentationValidator = new MdlPresentationValidator();
    return sdJwtPresentationValidator.validatePresentation(sdJwtPresentation,
        MdlPresentationValidationInput.builder()
            .nonce("1234567890_nonce")
            .responseUri("https://example.com/aud")
            .clientId("https://example.com/client")
            .mdocGeneratedNonce("0987654321_walletNonce")
            .build(), trustedKeys);
  }
```

Optional extension that can validate MAC as well as device signatures as means of validating that the token is bound to the wallet private key.

```java
  MdlPresentationValidationResult validateMdocPresentationWithMac(byte[] sdJwtPresentation,
      List<TrustedKey> trustedKeys) throws Exception
  {
    MdlPresentationValidator sdJwtPresentationValidator = new MdlPresentationValidator();
    return sdJwtPresentationValidator.validatePresentation(sdJwtPresentation,
        MdlPresentationValidationInput.builder()
            .nonce("1234567890_nonce")
            .responseUri("https://example.com/aud")
            .clientId("https://example.com/client")
            .mdocGeneratedNonce("0987654321_walletNonce")
            .clientPrivateKey(clientKeyPair.toPrivateKey())
            .build(), trustedKeys);
  }
```

Note that the MAC option has the slight added feature of also binding the presentation to the requester private key and ensures that only the legitimate intended recipient can validate the MAC.

[Development](./docs/DEVELOPMENT.md)

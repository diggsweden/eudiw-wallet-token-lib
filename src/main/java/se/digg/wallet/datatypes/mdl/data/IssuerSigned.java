// SPDX-FileCopyrightText: 2024 Digg - Agency for Digital Government
//
// SPDX-License-Identifier: EUPL-1.2

package se.digg.wallet.datatypes.mdl.data;

import com.fasterxml.jackson.core.*;
import com.fasterxml.jackson.databind.JsonSerializer;
import com.fasterxml.jackson.databind.SerializerProvider;
import com.fasterxml.jackson.databind.annotation.JsonSerialize;
import com.fasterxml.jackson.dataformat.cbor.CBORGenerator;
import com.upokecenter.cbor.CBORObject;
import java.io.IOException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.cert.CertificateEncodingException;
import java.time.Duration;
import java.time.Instant;
import java.util.*;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;
import se.digg.wallet.datatypes.common.TokenParsingException;
import se.digg.wallet.datatypes.common.TokenSigningAlgorithm;
import se.idsec.cose.COSEKey;
import se.idsec.cose.CoseException;
import se.swedenconnect.security.credential.PkiCredential;

@Data
@AllArgsConstructor
@NoArgsConstructor
@JsonSerialize(using = IssuerSigned.Serializer.class)
public class IssuerSigned {

  /** Map of name spaces. Each name space lists a set of attributes under that name space */
  Map<String, List<IssuerSignedItem>> nameSpaces;
  /** Utagged Sign1 COSE signature where payload is CBOR encoding of @{@link MobileSecurityObject} */
  byte[] issuerAuth;

  public static IssuerSignedBuilder builder() {
    return new IssuerSignedBuilder();
  }

  public static class IssuerSignedBuilder {

    private final IssuerSigned issuerSigned;
    private PkiCredential issuerCredential;
    private TokenSigningAlgorithm signingAlgorithm;
    private MobileSecurityObject.MobileSecurityObjectBuilder msoBuilder;

    private String version;
    private String docType;

    private String signingKid;

    private boolean protectedKid = false;

    private IssuerSignedBuilder() {
      this.issuerSigned = new IssuerSigned();
    }

    public IssuerSignedBuilder nameSpace(
      String namespace,
      List<IssuerSignedItem> issuerSignedItems
    ) {
      Map<String, List<IssuerSignedItem>> namespaceMap = Optional.ofNullable(
        issuerSigned.getNameSpaces()
      ).orElse(new HashMap<>());
      namespaceMap.put(namespace, issuerSignedItems);
      this.issuerSigned.nameSpaces = namespaceMap;
      return this;
    }

    /**
     * Sets the namespaces for the IssuerSignedBuilder. If you use this function after using the function "nameSpace()", then those
     * settings will be lost.
     *
     * @param nameSpaces a map containing namespace as key and list of IssuerSignedItem objects as value
     * @return IssuerSignedBuilder instance with the updated namespaces
     */
    public IssuerSignedBuilder namespaces(
      Map<String, List<IssuerSignedItem>> nameSpaces
    ) {
      this.issuerSigned.nameSpaces = nameSpaces;
      return this;
    }

    public IssuerSignedBuilder issuerAuthInput(
      PkiCredential issuerCredential,
      TokenSigningAlgorithm signingAlgorithm,
      PublicKey walletPublicKey,
      Duration validity,
      String signingKid
    ) throws CoseException {
      return issuerAuthInput(
        issuerCredential,
        signingAlgorithm,
        walletPublicKey,
        validity,
        "eu.europa.ec.eudi.pid.1",
        "1.0",
        signingKid
      );
    }

    public IssuerSignedBuilder issuerAuthInput(
      PkiCredential issuerCredential,
      TokenSigningAlgorithm signingAlgorithm,
      PublicKey walletPublicKey,
      Duration validity,
      String docType,
      String version,
      String signingKid
    ) throws CoseException {
      Objects.requireNonNull(issuerCredential);
      Objects.requireNonNull(signingAlgorithm);
      Objects.requireNonNull(validity);
      this.issuerCredential = issuerCredential;
      this.signingAlgorithm = signingAlgorithm;
      this.docType = docType;
      this.version = version;
      this.signingKid = signingKid;
      this.msoBuilder = MobileSecurityObject.builder()
        .validityInfo(
          MobileSecurityObject.ValidityInfo.builder()
            .validFrom(Instant.now())
            .validUntil(Instant.now().plus(validity))
            .build()
        );
      if (walletPublicKey != null) {
        this.msoBuilder.deviceKeyInfo(
            MobileSecurityObject.DeviceKeyInfo.builder()
              .deviceKey(new COSEKey(walletPublicKey, null))
              .build()
          );
      }
      return this;
    }

    /**
     * Sets if any KID should be placed in a protected header. Default false.
     *
     * @param protectedKid a value of true will place KID in a protected COSE header
     * @return this builder
     */
    public IssuerSignedBuilder protectedKid(boolean protectedKid) {
      this.protectedKid = protectedKid;
      return this;
    }

    public IssuerSigned build()
      throws CoseException, IOException, CertificateEncodingException {
      Map<String, List<IssuerSignedItem>> nameSpaces =
        this.issuerSigned.getNameSpaces();
      if (nameSpaces == null) {
        throw new IllegalStateException(
          "NameSpaces must be set before building IssuerSigned"
        );
      }
      if (issuerCredential != null) {
        // If issuer credential is set, sign document
        COSEKey signingKey = new COSEKey(
          issuerCredential.getPublicKey(),
          issuerCredential.getPrivateKey()
        );
        Map<String, Map<Integer, byte[]>> attributeEntryHashMap =
          new HashMap<>();
        for (Map.Entry<
          String,
          List<IssuerSignedItem>
        > nameSpaceEntry : nameSpaces.entrySet()) {
          String nameSpace = nameSpaceEntry.getKey();
          attributeEntryHashMap.put(nameSpace, new HashMap<>());
          for (IssuerSignedItem attributeInfo : nameSpaceEntry.getValue()) {
            MessageDigest digest;
            try {
              digest = MessageDigest.getInstance(
                signingAlgorithm.getDigestAlgorithm().getJdkName()
              );
            } catch (NoSuchAlgorithmException e) {
              throw new RuntimeException(e);
            }
            byte[] attributeHashValue = digest.digest(
              attributeInfo.toBeHashedBytes()
            );
            attributeEntryHashMap
              .get(nameSpace)
              .put(attributeInfo.getDigestID(), attributeHashValue);
          }
        }
        MobileSecurityObject mso = msoBuilder
          .digestAlgorithm(signingAlgorithm.getDigestAlgorithm().getMdlName())
          .valueDigests(attributeEntryHashMap)
          .version(version)
          .docType(docType)
          .build();
        mso.getValidityInfo().setSigned(Instant.now());
        byte[] coseSignature = mso
          .sign(
            issuerCredential.getCertificateChain(),
            signingKey,
            signingAlgorithm.getAlgorithmID(),
            signingKid,
            protectedKid
          )
          .EncodeToBytes();
        issuerSigned.setIssuerAuth(coseSignature);
      }
      return issuerSigned;
    }
  }

  public static class Serializer extends JsonSerializer<IssuerSigned> {

    @Override
    public void serialize(
      IssuerSigned issuerSigned,
      JsonGenerator gen,
      SerializerProvider serializers
    ) throws IOException {
      CBORObject map = CBORObject.NewOrderedMap();
      CBORObject nameSpaceMap = CBORObject.NewOrderedMap();
      for (Map.Entry<String, List<IssuerSignedItem>> entry : issuerSigned
        .getNameSpaces()
        .entrySet()) {
        CBORObject itemList = CBORObject.NewArray();
        for (IssuerSignedItem item : entry.getValue()) {
          itemList.Add(CBORObject.DecodeFromBytes(item.toBeHashedBytes()));
        }
        nameSpaceMap.set(entry.getKey(), itemList);
      }
      map.set("nameSpaces", nameSpaceMap);
      if (issuerSigned.getIssuerAuth() != null) {
        map.set(
          "issuerAuth",
          CBORObject.DecodeFromBytes(issuerSigned.getIssuerAuth())
        );
      }

      // Generate serialized CBOR bytes
      byte[] value = map.EncodeToBytes();

      if (gen instanceof CBORGenerator cborGen) {
        cborGen.writeBytes(value, 0, value.length);
      } else {
        // Handle non-CBOR case, throw exception
        throw new JsonGenerationException("Non-CBOR generator used", gen);
      }
    }
  }

  public static IssuerSigned deserialize(byte[] cborEncoded)
    throws TokenParsingException {
    // Parse CBOR
    try {
      CBORObject cbor = CBORObject.DecodeFromBytes(cborEncoded);

      // Extract values from the CBOR Object
      CBORObject nameSpacesCbor = cbor.get("nameSpaces");
      Map<String, List<IssuerSignedItem>> nameSpaces = new HashMap<>();
      for (CBORObject key : nameSpacesCbor.getKeys()) {
        CBORObject listObj = nameSpacesCbor.get(key);
        List<IssuerSignedItem> list = new ArrayList<>();
        for (int i = 0; i < listObj.size(); i++) {
          byte[] itemBytes = listObj.get(i).EncodeToBytes();
          IssuerSignedItem item = CBORUtils.CBOR_MAPPER.readValue(
            itemBytes,
            IssuerSignedItem.class
          );
          list.add(item);
        }
        nameSpaces.put(key.AsString(), list);
      }

      byte[] issuerAuth = cbor.get("issuerAuth").EncodeToBytes();

      // Construct and return IssuerSigned
      IssuerSigned issuerSigned = new IssuerSigned();
      issuerSigned.setNameSpaces(nameSpaces);
      issuerSigned.setIssuerAuth(issuerAuth);
      return issuerSigned;
    } catch (Exception e) {
      throw new TokenParsingException("Failed to parse IssuerSigned", e);
    }
  }
}

// SPDX-FileCopyrightText: 2024 Digg - Agency for Digital Government
//
// SPDX-License-Identifier: EUPL-1.2

package se.digg.wallet.datatypes.mdl.data;

import com.fasterxml.jackson.core.JsonGenerationException;
import com.fasterxml.jackson.core.JsonGenerator;
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
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;
import se.digg.cose.COSEKey;
import se.digg.cose.CoseException;
import se.digg.wallet.datatypes.common.TokenParsingException;
import se.digg.wallet.datatypes.common.TokenSigningAlgorithm;
import se.swedenconnect.security.credential.PkiCredential;

/**
 * Represents an issuer-signed data structure representing the token issuer contribution to the
 * presentation of a token with disclosure data. The Issuer-signed object contains a map of namespaces
 * and their corresponding attributes, along with a COSE signature.
 * This class is designed to serialize and deserialize data in CBOR format
 * while maintaining cryptographic integrity through COSE signatures.
 */
@Data
@AllArgsConstructor
@NoArgsConstructor
@JsonSerialize(using = IssuerSigned.Serializer.class)
public class IssuerSigned {

  /** Map of name spaces. Each name space lists a set of attributes under that name space */
  Map<String, List<IssuerSignedItem>> nameSpaces;
  /** Utagged Sign1 COSE signature where payload is CBOR encoding of @{@link MobileSecurityObject} */
  byte[] issuerAuth;

  /**
   * Creates a new builder instance for constructing an {@code IssuerSigned} object.
   *
   * @return a new {@code IssuerSignedBuilder} instance for building an {@code IssuerSigned} object
   */
  public static IssuerSignedBuilder builder() {
    return new IssuerSignedBuilder();
  }

  /**
   * A builder class for constructing instances of {@code IssuerSigned}. This builder enables the configuration
   * of namespaces, issuer authentication details, document type, version, signing key, and other related
   * properties. It provides an encapsulated approach to creating and initializing an {@code IssuerSigned} object,
   * ensuring the consistency of its configuration.
   */
  public static class IssuerSignedBuilder {

    /** The object being built */
    private final IssuerSigned issuerSigned;
    /** The credential of the issuer being used to sign data */
    private PkiCredential issuerCredential;
    /** The signing algorithm */
    private TokenSigningAlgorithm signingAlgorithm;
    /** A builder for creating the data to be signed by the issuer */
    private MobileSecurityObject.MobileSecurityObjectBuilder msoBuilder;
    /** Version information for the issuer-signed object */
    private String version;
    /** DocType declaration */
    private String docType;
    /** Key identifier to include in the signature header */
    private String signingKid;
    /** true if the key identifier should be present in a protected header */
    private boolean protectedKid = false;

    /**
     * Default private constructor for IssuerSignedBuilder.
     * Initializes the builder by creating a new instance of the IssuerSigned object.
     * This constructor is used internally and prevents direct instantiation of the IssuerSignedBuilder class
     * from outside the class. Use the provided public methods to configure and build an IssuerSigned object.
     */
    private IssuerSignedBuilder() {
      this.issuerSigned = new IssuerSigned();
    }

    /**
     * Adds or updates a namespace in the issuerSigned object with the provided list of IssuerSignedItem objects.
     *
     * @param namespace the name of the namespace to be added or updated
     * @param issuerSignedItems the list of IssuerSignedItem objects to associate with the specified namespace
     * @return the current instance of the IssuerSignedBuilder with the updated namespace configuration
     */
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

    /**
     * Provide the necessary input required to create the issuer signature in the issuerAuth component of the
     * IssuerSigned object.
     *
     * @param issuerCredential the PKI credential of the issuer, which is required to sign the objects
     * @param signingAlgorithm the cryptographic signing algorithm to be used for token signing
     * @param walletPublicKey the public key of the wallet used for the authentication process
     * @param validity the duration for which the signed object will remain valid
     * @param signingKid the key identifier (KID) for the signing key
     * @return the updated instance of IssuerSignedBuilder after applying the authentication input configuration
     * @throws CoseException if an error occurs during the construction of cryptographic components
     */
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

    /**
     * Configures the issuer authentication inputs required to create the issuer signature
     * in the issuerAuth component of the IssuerSigned object.
     *
     * @param issuerCredential the PKI credential of the issuer, necessary for signing objects
     * @param signingAlgorithm the cryptographic signing algorithm to be used for token signing
     * @param walletPublicKey the public key of the wallet used in the authentication process; can be null
     * @param validity the duration for which the signed object will remain valid
     * @param docType the document type associated with the IssuerSigned object
     * @param version the version of the document to be signed
     * @param signingKid the key identifier (KID) for the signing key
     * @return the updated instance of IssuerSignedBuilder with the configured issuer authentication inputs
     * @throws CoseException if an error occurs during the construction of cryptographic components
     */
    public IssuerSignedBuilder issuerAuthInput(
      PkiCredential issuerCredential,
      TokenSigningAlgorithm signingAlgorithm,
      PublicKey walletPublicKey,
      Duration validity,
      String docType,
      String version,
      String signingKid
    ) throws CoseException {
      Objects.requireNonNull(issuerCredential, "issuerCredential must be set");
      Objects.requireNonNull(signingAlgorithm, "signingAlgorithm must be set");
      Objects.requireNonNull(validity, "validity must be set");
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

    /**
     * Builds and returns the {@link IssuerSigned} object using the provided configurations.
     * Validates that all necessary fields have been set and computes any required cryptographic
     * signatures using the issuer credentials and signing algorithm if provided.
     *
     * @return the fully constructed {@link IssuerSigned} object
     * @throws CoseException if an error occurs during the creation or signing of cryptographic components
     * @throws IOException if an input/output error occurs
     * @throws CertificateEncodingException if there is an error in encoding the issuer's certificate
     */
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

  /**
   * Serializer class for serializing {@link IssuerSigned} objects into CBOR format.
   * This class extends the {@link JsonSerializer} to provide custom serialization logic
   * for {@code IssuerSigned} objects.
   */
  public static class Serializer extends JsonSerializer<IssuerSigned> {

    /** {@inheritDoc} */
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

  /**
   * Deserializes a CBOR-encoded byte array into an {@code IssuerSigned} object.
   *
   * @param cborEncoded the CBOR-encoded byte array representing the {@code IssuerSigned} object
   * @return the deserialized {@code IssuerSigned} object
   * @throws TokenParsingException if the byte array could not be parsed or if the deserialization process fails
   */
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

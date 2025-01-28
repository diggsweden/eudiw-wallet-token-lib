/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package se.idsec.cose;

import java.util.ArrayList;
import java.util.List;
import com.upokecenter.cbor.CBORObject;
import com.upokecenter.cbor.CBORType;

/**
 * The SignCOSEObject class is used to implement the COSE_Sign object.
 * This provides for a signed object with content and one or more signatures attached.
 * The signatures can be either from a single signer or from multiple different signers.
 * In the case where only one signature is required and the signer can be implicitly known, {@link Sign1COSEObject} can be used instead.
 * There is no way to convert a signed message between the two formats.
 * <p>
 * Create a SignCOSEObject object for a new message, when processing an existing message use COSEObject.DecodeFromBytes to create a SignCOSEObject object.
 * <p>
 * Examples can be found at<br>
 * <a href="https://github.com/cose-wg/COSE-JAVA/wiki/Sign-Message-Example">Single Signer Example</a> an example of signing and verify a message with a single signature.
 * <br><a href="https://github.com/cose-wg/COSE-JAVA/wiki/Multi-Sign-Example">Multiple Signer Example</a> an example of signing and verifying a message which has multiple signatures.
 * 
 * @author jimsch
 */
public class SignCOSEObject extends COSEObject {
    protected List<Signer> signerList = new ArrayList<Signer>();
    
    /**
     * Create a signed message object for which the leading tag and the content will be included.
     */
    
    public SignCOSEObject() {
        coseObjectTag = COSEObjectTag.Sign;
    }
    
    /**
     * Create a signed message object for which the emission of the leading tag and content is controlled by the parameters.
     * 
     * @param emitTagIn emit leading tag when message is serialized
     * @param emitContentIn emit the content as part of the message
     */
    
    public SignCOSEObject(boolean emitTagIn, boolean emitContentIn) {
        coseObjectTag = COSEObjectTag.Sign;
        emitTag = emitTagIn;
        emitContent = emitContentIn;
    }
            
    /**
     * Internal function used in creating a SignCOSEObject object from a byte string.
     * 
     * @param obj COSE_Sign encoded object.
     * @throws CoseException Errors generated by the COSE module
     */
    @Override
    protected void DecodeFromCBORObject(CBORObject obj) throws CoseException {
        if (obj.size() != 4) throw new CoseException("Invalid SignCOSEObject structure");
        
        if (obj.get(0).getType() == CBORType.ByteString) {
            rgbProtected = obj.get(0).GetByteString();
            if (obj.get(0).GetByteString().length == 0) {
                objProtected = CBORObject.NewMap();
            }
            else {
                objProtected = CBORObject.DecodeFromBytes(rgbProtected);
                if (objProtected.size() == 0) rgbProtected = new byte[0];
            }
        }
        else throw new CoseException("Invalid SignCOSEObject structure");
        
        if (obj.get(1).getType() == CBORType.Map) {
            objUnprotected = obj.get(1);
        }
        else throw new CoseException("Invalid SignCOSEObject structure");
        
        if (obj.get(2).getType() == CBORType.ByteString) rgbContent = obj.get(2).GetByteString();
        else if (!obj.get(2).isNull()) throw new CoseException("Invalid SignCOSEObject structure");
        
        if (obj.get(3).getType() == CBORType.Array) {
            for (int i=0; i<obj.get(3).size(); i++) {
                Signer signer = new Signer();
                signer.DecodeFromCBORObject(obj.get(3).get(i));
                signerList.add(signer);
            }
        }
        else throw new CoseException("Invalid SignCOSEObject structure");
    }

    /**
     * Internal function used to create a serialization of a COSE_Sign message
     * 
     * @return CBOR object which can be encoded.
     * @throws CoseException Errors generated by the COSE module
     */
    @Override
    protected CBORObject EncodeCBORObject() throws CoseException {
        sign();
        
        CBORObject obj = CBORObject.NewArray();
        
        obj.Add(rgbProtected);
        obj.Add(objUnprotected);
        if (emitContent) obj.Add(rgbContent);
        else obj.Add(null);
        CBORObject signers = CBORObject.NewArray();
        obj.Add(signers);
        
        for (Signer r : signerList) {
            signers.Add(r.EncodeToCBORObject());
        }
        
        return obj;
    }
    
    /**
     * Add a new signer to the message.  The details of the signer are provided
     * by the Signer object being added.
     * 
     * @param signedBy provides a Signer object containing details for the signer
     */
    
    public void AddSigner(Signer signedBy) {
        signerList.add(signedBy);
    }
    
    /**
     * Return the i-th signer of the message.
     * 
     * @param iSigner - which signer to be returned
     * @return Signer object
     */
    public Signer getSigner(int iSigner) {
      return signerList.get(iSigner);
    }
    
    /**
     * Return the number of signers on the message
     * 
     * @return number of elements in the signer list
     */
    public int getSignerCount() {
        return signerList.size();
    }
    
    /**
     * Return the list of signers on the message
     * 
     * @return a list of all of the Signer objects.
     */
    public List<Signer> getSignerList() {
        return signerList;
    }
    
    /**
     * Causes a signature to be created for every signer that does not already have one.
     * 
     * @throws CoseException Errors generated by the COSE module
     */
    public void sign() throws CoseException {
        if (rgbProtected == null) {
            if (objProtected.size() == 0) rgbProtected = new byte[0];
            else rgbProtected = objProtected.EncodeToBytes();
        }
        
        for (Signer r : signerList) {
            r.sign(rgbProtected, rgbContent);
        }
        
        ProcessCounterSignatures();
    }
    
    /**
     * Validate the signature on a message for a specific signer.
     * The signer is required to be one of the Signer objects attached to the message.
     * The key must be attached to the signer before making this call.
     * 
     * @param signerToUse which signer to validate with
     * @return true if the message validates with the signer
     * @throws CoseException Errors generated by the COSE module
     */
    
    public boolean validate(Signer signerToUse) throws CoseException {
        for (Signer r : signerList) {
            if (r == signerToUse) {
                return r.validate(rgbProtected, rgbContent);
            }
        }
        
        throw new CoseException("Signer not found");
    }
}

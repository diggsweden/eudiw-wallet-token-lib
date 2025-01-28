/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package se.idsec.cose;

import com.upokecenter.cbor.CBORObject;
import com.upokecenter.cbor.CBORType;

/**
 *
 * @author Jim
 */
public class CounterSign1 extends Signer {
    public CounterSign1()
    {
        contextString = "CounterSignature0";
    }
    
    public CounterSign1(byte[] rgb) {
        contextString = "CounterSignature0";
        rgbSignature = rgb;
        rgbProtected = new byte[0];
    }
    
    public CounterSign1(COSEKey key) {
        super(key);
        contextString = "CounterSignature0";
        objUnprotected.Clear();
        objProtected.Clear();
    }
    
    private COSEObject m_msgToSign;
    private Signer m_signerToSign;
    
    public void setObject(COSEObject msg)
    {
        m_msgToSign = msg;
    }
    
    public void setObject(Signer signer)
    {
        m_signerToSign = signer;
    }
    
    public void setKey(COSEKey key)
    {
        cnKey = key;
    }
    
    @Override
    public void DecodeFromCBORObject(CBORObject cbor) throws CoseException {
        if (cbor.getType() != CBORType.ByteString) {
            throw new CoseException("Invalid format for Countersignature0");
        }
        
        rgbSignature = cbor.GetByteString();
        rgbProtected = new byte[0];
    }
    
    public CBORObject EncodeToCBORObject() throws CoseException {
        if (!objProtected.getValues().isEmpty() || !objUnprotected.getValues().isEmpty()) {
            throw new CoseException("CounterSign1 object cannot have protected or unprotected attributes");
        }
        
        return CBORObject.FromObject(rgbSignature);
    }
            
}

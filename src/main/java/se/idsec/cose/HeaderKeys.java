/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package se.idsec.cose;

import com.upokecenter.cbor.CBORObject;

/**
 *
 * @author jimsch
 */
public enum HeaderKeys {
    Algorithm(1),
    CONTENT_TYPE(3),
    KID(4),
    IV(5),
    CriticalHeaders(2),
    CounterSignature(7),
    PARTIAL_IV(6),
    CounterSignature0(9),

    /** An unordered bag of X.509 certificates. Encoded as bstring or an array when more than one certificate is conveyed */
    x5bag(32),
    /** An ordered chain of X.509 certificates. Encoded as bstring or an array when more than one certificate is conveyed */
    x5chain(33),
    /** Hash of an X.509 certificate */
    x5t(34),
    /** URI pointing to an X.509 certificate */
    x5u(35),

    ECDH_EPK(-1),
    ECDH_SPK(-2),
    ECDH_SKID(-3),

    HKDF_Salt(-20),
    HKDF_Context_PartyU_ID(-21),
    HKDF_Context_PartyU_nonce(-22),
    HKDF_Context_PartyU_Other(-23),
    HKDF_Context_PartyV_ID(-24),
    HKDF_Context_PartyV_nonce(-25),
    HKDF_Context_PartyV_Other(-26),

    HKDF_SuppPub_Other(-999),
    HKDF_SuppPriv_Other(-998)
    ;
    
    private CBORObject value;
    
    HeaderKeys(int val) {
        this.value = CBORObject.FromObject(val);
    }
    
    public CBORObject AsCBOR() {
        return value;
    }
}

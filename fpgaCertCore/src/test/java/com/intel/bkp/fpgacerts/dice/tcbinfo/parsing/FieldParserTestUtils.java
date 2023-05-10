/*
 * This project is licensed as below.
 *
 * **************************************************************************
 *
 * Copyright 2020-2023 Intel Corporation. All Rights Reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice,
 * this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright
 * notice, this list of conditions and the following disclaimer in the
 * documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A
 * PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER
 * OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL,
 * EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
 * PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS;
 * OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY,
 * WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR
 * OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF
 * ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 * **************************************************************************
 *
 */

package com.intel.bkp.fpgacerts.dice.tcbinfo.parsing;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.ASN1TaggedObject;
import org.bouncycastle.asn1.DERBitString;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DLSequence;
import org.bouncycastle.asn1.DLTaggedObject;

import static com.intel.bkp.utils.ByteConverter.toBytes;
import static com.intel.bkp.utils.HexConverter.fromHex;

class FieldParserTestUtils {

    public static ASN1TaggedObject getTaggedObject(ASN1Primitive obj) {
        return new DLTaggedObject(false, 1, obj);
    }

    public static ASN1ObjectIdentifier getAsn1ObjectIdentifier(String str) {
        return new ASN1ObjectIdentifier(str);
    }

    public static DEROctetString getOctetString(String hexStr) {
        return getOctetString(fromHex(hexStr));
    }

    public static DEROctetString getOctetString(Integer integer) {
        return getOctetString(toBytes(integer));
    }

    public static DEROctetString getOctetString(byte[] value) {
        return new DEROctetString(value);
    }

    public static DERBitString getBitString(String dataHex, int padBits) {
        return new DERBitString(fromHex(dataHex), padBits);
    }

    public static ASN1Sequence getSequence(ASN1Primitive... elements) {
        return new DLSequence(elements);
    }

    public static ASN1Sequence getFwIdSequence(ASN1ObjectIdentifier hashAlg, DEROctetString digest) {
        return getSequence(hashAlg, digest);
    }

    public static ASN1TaggedObject getFwIdsSequence(ASN1Sequence... fwIds) {
        return getTaggedSequence(fwIds);
    }

    public static ASN1TaggedObject getTaggedSequence(ASN1Primitive... elements) {
        return getTaggedObject(new DLSequence(elements));
    }
}

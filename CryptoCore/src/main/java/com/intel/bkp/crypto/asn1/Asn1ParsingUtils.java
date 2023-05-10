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

package com.intel.bkp.crypto.asn1;

import lombok.AccessLevel;
import lombok.NoArgsConstructor;
import org.bouncycastle.asn1.ASN1BitString;
import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Encoding;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1OutputStream;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.ASN1TaggedObject;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.DLSequence;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.util.Locale;

import static org.bouncycastle.asn1.BERTags.OCTET_STRING;

@NoArgsConstructor(access = AccessLevel.PRIVATE)
public class Asn1ParsingUtils {

    public static ASN1Encodable parseSingleElementSequence(ASN1Encodable asn1Encodable) {
        final ASN1Sequence sequence = parseSequence(asn1Encodable);

        if (sequence.size() != 1) {
            throw new IllegalArgumentException(String.format(
                "Extension has more than one field in sequence: %s", sequence));
        }

        return sequence.getObjectAt(0);
    }

    public static ASN1Sequence parseSequence(ASN1Encodable asn1Encodable) {
        return DLSequence.getInstance(asn1Encodable);
    }

    public static String parseAsn1Identifier(ASN1Encodable object) {
        return ASN1ObjectIdentifier.getInstance(object).getId().toUpperCase(Locale.ROOT);
    }

    public static byte[] parseImplicitlyTaggedOctetString(ASN1TaggedObject asn1TaggedObject) {
        return parseOctetString(asn1TaggedObject.getBaseUniversal(false, OCTET_STRING));
    }

    public static byte[] parseOctetString(ASN1Encodable asn1Encodable) {
        return DEROctetString.getInstance(asn1Encodable).getOctets();
    }

    public static byte[] parseBitString(ASN1TaggedObject asn1TaggedObject) {
        // NOTE: Includes padding bits in result
        return ASN1BitString.getInstance(asn1TaggedObject, false).getBytes();
    }

    public static byte[] extractR(byte[] signature) {
        return extractAsn1ObjectAtIndex(signature, 0);
    }

    public static byte[] extractS(byte[] signature) {
        return extractAsn1ObjectAtIndex(signature, 1);
    }

    public static byte[] convertToDerSignature(byte[] partR, byte[] partS) throws IOException {
        try (ByteArrayOutputStream byteArrayOutputStream = new ByteArrayOutputStream()) {
            ASN1OutputStream derOutputStream = ASN1OutputStream.create(byteArrayOutputStream, ASN1Encoding.DER);
            ASN1EncodableVector vector = new ASN1EncodableVector();
            vector.add(new ASN1Integer(new BigInteger(1, partR)));
            vector.add(new ASN1Integer(new BigInteger(1, partS)));
            derOutputStream.writeObject(new DERSequence(vector));
            return byteArrayOutputStream.toByteArray();
        }
    }

    private static byte[] extractAsn1ObjectAtIndex(byte[] signature, int index) {
        return ASN1Integer.getInstance(DERSequence.getInstance(signature).getObjectAt(index))
            .getPositiveValue()
            .toByteArray();
    }
}

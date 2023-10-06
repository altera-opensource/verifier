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

/*
 * Copyright (c) 2016,
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * * Redistributions of source code must retain the above copyright notice, this
 *   list of conditions and the following disclaimer.
 *
 * * Redistributions in binary form must reproduce the above copyright notice,
 *   this list of conditions and the following disclaimer in the documentation
 *   and/or other materials provided with the distribution.
 *
 * * Neither the name of COSE-JAVA nor the names of its
 *   contributors may be used to endorse or promote products derived from
 *   this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
 * SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
 * CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
 * OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

package com.intel.bkp.fpgacerts.cbor.signer.cose;

import com.intel.bkp.fpgacerts.cbor.signer.cose.exception.CoseException;
import com.intel.bkp.fpgacerts.cbor.signer.cose.model.KeyKeys;
import com.intel.bkp.fpgacerts.cbor.signer.cose.model.TagValue;
import com.upokecenter.cbor.CBORObject;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import static com.intel.bkp.utils.HexConverter.fromHex;

public class RimAsn1 {

    // 1.2.840.10045.3.1.7
    public static final byte[] OID_SECP_256_R1 = fromHex("06082A8648CE3D030107");
    // 1.3.132.0.34
    public static final byte[] OID_SECP_384_R1 = fromHex("06052B81040022");
    // 1.3.132.0.35
    public static final byte[] OID_SECP_521_R1 = fromHex("06052B81040023");
    // 1.2.840.10045.2.1
    public static final byte[] OID_EC_PUBLIC_KEY = fromHex("06072A8648CE3D0201");

    private static final byte[] SEQUENCE_TAG = fromHex("30");
    private static final int ASN1_ENCODING_MASK = 0x20;
    private static final int INTEGER_TAG = 2;

    public static CBORObject oidToCborEcCurve(byte[] oid) throws CoseException {
        if (Arrays.equals(oid, RimAsn1.OID_SECP_256_R1)) {
            return KeyKeys.EC2_P256;
        } else if (Arrays.equals(oid, RimAsn1.OID_SECP_384_R1)) {
            return KeyKeys.EC2_P384;
        } else if (Arrays.equals(oid, RimAsn1.OID_SECP_521_R1)) {
            return KeyKeys.EC2_P521;
        } else {
            throw new CoseException("Unsupported curve");
        }
    }

    public static List<TagValue> decodeSubjectPublicKeyInfo(byte[] encoding) throws CoseException {
        TagValue spki = decodeCompound(0, encoding);
        if (spki.getTag() != 0x30) {
            throw new CoseException("Invalid SPKI");
        }
        List<TagValue> tvl = spki.getTags();
        if (tvl.size() != 2) {
            throw new CoseException("Invalid SPKI");
        }

        if (tvl.get(0).getTag() != 0x30) {
            throw new CoseException("Invalid SPKI");
        }
        if (tvl.get(0).getTags().isEmpty() || tvl.get(0).getTags().size() > 2) {
            throw new CoseException("Invalid SPKI");
        }
        if (tvl.get(0).getTags().get(0).getTag() != 6) {
            throw new CoseException("Invalid SPKI");
        }
        //  tvl.get(0).list.get(1).tag is an ANY so needs to be checked elsewhere
        if (tvl.get(1).getTag() != 3) {
            throw new CoseException("Invalid SPKI");
        }

        return tvl;
    }

    public static TagValue decodeCompound(int offset, byte[] data) throws CoseException {
        final int retTag = data[offset];

        verifyStructure(offset, data);
        int[] length = decodeLength(offset + 1, data);
        int seqLength = length[1];
        verifySequence(offset, data, seqLength);
        offset += length[0] + 1;

        final List<TagValue> result = new ArrayList<>();
        while (seqLength > 0) {
            final var tag = data[offset];
            length = decodeLength(offset + 1, data);
            verifySequenceLength(length, seqLength);
            if (isComposedTag(tag)) {
                handleComposedTag(offset, data, result);
            } else {
                handleSimpleTag(offset, data, length, result, tag);
            }
            offset += 1 + length[0] + length[1];
            seqLength -= 1 + length[0] + length[1];
        }

        return new TagValue(retTag, result);
    }

    private static void verifySequenceLength(int[] length, int sequenceLength) throws CoseException {
        if (length[1] > sequenceLength) {
            throw new CoseException("Invalid sequence");
        }
    }

    private static void verifySequence(int offset, byte[] encoding, int sequenceLength) throws CoseException {
        if (offset + sequenceLength > encoding.length) {
            throw new CoseException("Invalid sequence");
        }
    }

    private static void verifyStructure(int offset, byte[] encoding) throws CoseException {
        if ((encoding[offset] & ASN1_ENCODING_MASK) != ASN1_ENCODING_MASK) {
            throw new CoseException("Invalid structure");
        }
    }

    private static boolean isComposedTag(int tag) {
        return (tag & ASN1_ENCODING_MASK) != 0;
    }

    private static void handleComposedTag(int offset, byte[] encoding, List<TagValue> result) throws CoseException {
        result.add(decodeCompound(offset, encoding));
    }

    private static void handleSimpleTag(int offset, byte[] encoding, int[] length, List<TagValue> result, int tag) {
        int rangeFrom;
        int rangeTo;
        if (tag == 6) {
            rangeFrom = offset;
            rangeTo = offset + length[1] + length[0] + 1;
        } else {
            rangeFrom = offset + length[0] + 1;
            rangeTo = offset + 1 + length[0] + length[1];
        }
        result.add(new TagValue(tag, Arrays.copyOfRange(encoding, rangeFrom, rangeTo)));
    }

    public static TagValue decodeSimple(int offset, byte[] encoding) throws CoseException {
        if (encoding[offset] != 0x04) {
            throw new CoseException("Invalid structure");
        }
        int[] l = decodeLength(offset + 1, encoding);

        int sequenceLength = l[1];
        if (offset + 2 + sequenceLength != encoding.length) {
            throw new CoseException("Invalid sequence");
        }

        int tag = encoding[offset];
        offset += 1 + l[0];
        final List<TagValue> result = List.of(
            new TagValue(tag, Arrays.copyOfRange(encoding, offset, offset + l[1]))
        );

        int retTag = encoding[offset];
        return new TagValue(retTag, result);
    }

    public static List<TagValue> decodePKCS8Structure(byte[] encodedData) throws CoseException {
        TagValue pkcs8 = decodeCompound(0, encodedData);
        if (pkcs8.getTag() != 0x30) {
            throw new CoseException("Invalid PKCS8 structure");
        }
        List<TagValue> retValue = pkcs8.getTags();
        if (retValue.size() != 3 && retValue.size() != 4) {
            throw new CoseException("Invalid PKCS8 structure");
        }

        // Version number - we currently only support one version
        if (retValue.get(0).getTag() != INTEGER_TAG && retValue.get(0).getValue()[0] != 0) {
            throw new CoseException("Invalid PKCS8 structure");
        }

        // Algorithm identifier
        if (retValue.get(1).getTag() != 0x30) {
            throw new CoseException("Invalid PKCS8 structure");
        }
        if (retValue.get(1).getTags().isEmpty() || retValue.get(1).getTags().size() > 2) {
            throw new CoseException("Invalid PKCS8 structure");
        }
        if (retValue.get(1).getTags().get(0).getTag() != 6) {
            throw new CoseException("Invalid PKCS8 structure");
        }
        //  Dont check the next item as it is an ANY

        if (retValue.get(2).getTag() != 4) {
            throw new CoseException("Invalid PKCS8 structure");
        }

        // This is attributes, but we are not going to check for correctness.
        if (retValue.size() == 4 && retValue.get(3).getTag() != 0xa0) {
            throw new CoseException("Invalid PKCS8 structure");
        }

        return retValue;
    }

    public static List<TagValue> decodePKCS8EC(List<TagValue> pkcs8) throws CoseException {
        //  Decode the contents of the octet string PrivateKey

        byte[] pk = pkcs8.get(2).getValue();
        TagValue pkd;

        // First check if it can be decoded as a simple value
        if (pk[0] == 0x04) { // ASN.1 Octet string
            pkd = decodeSimple(0, pk);
            return pkd.getTags();
        }

        // Otherwise proceed to parse as compound value
        pkd = decodeCompound(0, pk);
        List<TagValue> pkdl = pkd.getTags();
        if (pkd.getTag() != 0x30) {
            throw new CoseException("Invalid ECPrivateKey");
        }
        if (pkdl.size() < 2 || pkdl.size() > 4) {
            throw new CoseException("Invalid ECPrivateKey");
        }

        if (pkdl.get(0).getTag() != 2 && pkcs8.get(0).getValue()[0] != 1) {
            throw new CoseException("Invalid ECPrivateKey");
        }

        if (pkdl.get(1).getTag() != 4) {
            throw new CoseException("Invalid ECPrivateKey");
        }

        if (pkdl.size() > 2) {
            if ((pkdl.get(2).getTag() & 0xff) != 0xA0) {
                if (pkdl.size() != 3 || (pkdl.get(2).getTag() & 0xff) != 0xa1) {
                    throw new CoseException("Invalid ECPrivateKey");
                }
            } else {
                if (pkdl.size() == 4 && (pkdl.get(3).getTag() & 0xff) != 0xa1) {
                    throw new CoseException("Invalid ECPrivateKey");
                }
            }
        }

        return pkdl;
    }

    public static byte[] encodeSignature(byte[] r, byte[] s) throws CoseException {
        List<byte[]> x = new ArrayList<>();
        x.add(unsignedInteger(r));
        x.add(unsignedInteger(s));

        return sequence(x);
    }

    private static byte[] sequence(List<byte[]> members) throws CoseException {
        byte[] y = toBytes(members);
        List<byte[]> x = new ArrayList<>();
        x.add(SEQUENCE_TAG);
        x.add(computeLength(y.length));
        x.add(y);

        return toBytes(x);
    }

    private static byte[] unsignedInteger(byte[] value) {

        int offset = 0;
        while (offset < value.length && value[offset] == 0) {
            offset++;
        }

        if (offset == value.length) {
            return new byte[]{0x02, 0x01, 0x00};
        }

        int pad = 0;
        if ((value[offset] & 0x80) != 0) {
            pad++;
        }

        // M00BUG if the integer is > 127 bytes long with padding

        int length = value.length - offset;
        byte[] der = new byte[2 + length + pad];
        der[0] = 0x02;
        der[1] = (byte) (length + pad);
        System.arraycopy(value, offset, der, 2 + pad, length);

        return der;
    }

    private static byte[] computeLength(int x) throws CoseException {
        if (x <= 127) {
            return new byte[]{(byte) x};
        } else if (x < 256) {
            return new byte[]{(byte) 0x81, (byte) x};
        }
        throw new CoseException("Error in ASN1.GetLength");
    }

    private static int[] decodeLength(int offset, byte[] data) throws CoseException {
        int length;

        final byte offsetByte = data[offset];

        if ((offsetByte & 0x80) == 0) {
            return new int[]{1, offsetByte};
        }
        if (offsetByte == (byte) 0x80) {
            throw new CoseException("Indefinite length encoding not supported");
        }

        length = offsetByte & 0x7f;
        int retValue = 0;
        for (int inc = 0; inc < length; inc++) {
            retValue = retValue * 256 + (data[inc + offset + 1] & 0xff);
        }

        return new int[]{length + 1, retValue};
    }

    private static byte[] toBytes(List<byte[]> x) {
        int l = 0;
        l = x.stream().map((r) -> r.length).reduce(l, Integer::sum);

        byte[] b = new byte[l];
        l = 0;
        for (byte[] r : x) {
            System.arraycopy(r, 0, b, l, r.length);
            l += r.length;
        }

        return b;
    }
}

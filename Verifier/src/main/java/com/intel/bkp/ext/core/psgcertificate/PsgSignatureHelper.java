/*
 * This project is licensed as below.
 *
 * **************************************************************************
 *
 * Copyright 2020-2021 Intel Corporation. All Rights Reserved.
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

package com.intel.bkp.ext.core.psgcertificate;

import com.intel.bkp.ext.core.psgcertificate.exceptions.PsgInvalidSignatureException;
import com.intel.bkp.ext.core.psgcertificate.model.PsgSignatureCurveType;
import lombok.AccessLevel;
import lombok.NoArgsConstructor;

import java.util.Arrays;

@NoArgsConstructor(access = AccessLevel.PRIVATE)
public class PsgSignatureHelper {

    private static final int SIGNATURE_METADATA_SIZE = 4 * Integer.BYTES; // 4 Integer fields
    static final int SIGNATURE_MAGIC = 0x74881520;

    public static void verifySignatureMagic(int signatureMagic) throws PsgInvalidSignatureException {
        if (SIGNATURE_MAGIC != signatureMagic) {
            throw new PsgInvalidSignatureException("Invalid signature magic");
        }
    }

    public static int getTotalSignatureSize(PsgSignatureCurveType curveType) {
        return (2 * curveType.getSize()) + SIGNATURE_METADATA_SIZE;
    }

    public static PsgSignatureCurveType parseSignatureType(int signatureHashMagic) throws PsgInvalidSignatureException {
        for (PsgSignatureCurveType curveType : PsgSignatureCurveType.values()) {
            if (curveType.getMagic() == signatureHashMagic) {
                return curveType;
            }
        }
        throw new PsgInvalidSignatureException("Invalid signature hash magic");
    }

    public static byte[] extractR(byte[] signature) {
        int startR = (signature[1] & 0x80) != 0 ? 3 : 2;
        int lengthR = signature[startR + 1];
        return Arrays.copyOfRange(signature, startR + 2, startR + 2 + lengthR);
    }

    public static byte[] extractS(byte[] signature) {
        int startR = (signature[1] & 0x80) != 0 ? 3 : 2;
        int lengthR = signature[startR + 1];

        int startS = startR + 2 + lengthR;
        int lengthS = signature[startS + 1];
        return Arrays.copyOfRange(signature, startS + 2, startS + 2 + lengthS);
    }
}

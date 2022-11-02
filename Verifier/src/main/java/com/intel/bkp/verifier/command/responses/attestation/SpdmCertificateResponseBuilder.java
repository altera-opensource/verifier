/*
 * This project is licensed as below.
 *
 * **************************************************************************
 *
 * Copyright 2020-2022 Intel Corporation. All Rights Reserved.
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

package com.intel.bkp.verifier.command.responses.attestation;

import com.intel.bkp.utils.ByteBufferSafe;
import com.intel.bkp.utils.ByteSwapOrder;
import com.intel.bkp.verifier.exceptions.VerifierRuntimeException;
import lombok.Getter;
import lombok.Setter;

import java.nio.ByteOrder;

import static com.intel.bkp.crypto.constants.CryptoConstants.SHA384_LEN;
import static com.intel.bkp.utils.ByteSwap.getSwappedArray;

@Getter
@Setter
public class SpdmCertificateResponseBuilder {

    private static final int TOTAL_LEN_LEN = Short.BYTES;
    private static final int RESERVED_LEN = 2;
    static final int CERT_CHAIN_HASH_LEN = SHA384_LEN;
    static final short TOTAL_LEN_OF_THIS_STRUCTURE_BASE = TOTAL_LEN_LEN + RESERVED_LEN + CERT_CHAIN_HASH_LEN;

    private short totalLenOfThisStructure = TOTAL_LEN_OF_THIS_STRUCTURE_BASE;
    private byte[] reserved = new byte[RESERVED_LEN];
    private byte[] certificateChainHash = new byte[CERT_CHAIN_HASH_LEN];
    private byte[] certificateChain = new byte[0];

    private static short setTotalLenOfThisStruct(int actualCertChainLen) {
        return (short) (TOTAL_LEN_OF_THIS_STRUCTURE_BASE + actualCertChainLen);
    }

    public SpdmCertificateResponseBuilder withCertificateChain(byte[] certificateChain) {
        final int actualCertChainLen = certificateChain.length;
        final int maxCertChainLen = Short.MAX_VALUE - TOTAL_LEN_OF_THIS_STRUCTURE_BASE;

        if (actualCertChainLen > maxCertChainLen) {
            throw new VerifierRuntimeException(
                "Certificate chain is too big. Max: %d, Actual: %d"
                    .formatted(maxCertChainLen, actualCertChainLen)
            );
        }

        this.certificateChain = certificateChain;
        this.totalLenOfThisStructure = setTotalLenOfThisStruct(actualCertChainLen);
        return this;
    }

    public SpdmCertificateResponseBuilder withCertificateChainHash(byte[] certificateChainHash) {
        ByteBufferSafe.wrap(certificateChainHash).getAll(this.certificateChainHash);
        return this;
    }

    public SpdmCertificateResponse build() {
        final var response = new SpdmCertificateResponse();
        response.setTotalLenOfThisStructure(getSwappedArray(totalLenOfThisStructure, ByteSwapOrder.B2L));
        response.setReserved(reserved);
        response.setCertificateChainHash(certificateChainHash);
        response.setCertificateChain(certificateChain);
        return response;
    }

    public SpdmCertificateResponseBuilder parse(byte[] message) {
        final ByteBufferSafe buffer = ByteBufferSafe.wrap(message);
        totalLenOfThisStructure = buffer.getShort(ByteOrder.LITTLE_ENDIAN);
        buffer.get(reserved);
        buffer.get(certificateChainHash);
        certificateChain = buffer.getRemaining();

        verifyTotalLen();

        return this;
    }

    private void verifyTotalLen() {
        final int actualTotalLen = certificateChain.length + TOTAL_LEN_LEN + RESERVED_LEN + CERT_CHAIN_HASH_LEN;
        if (totalLenOfThisStructure != actualTotalLen) {
            throw new VerifierRuntimeException("Certificate chain response has invalid total length. "
                + "Expected: %d, Actual: %d".formatted(totalLenOfThisStructure, actualTotalLen));
        }
    }
}

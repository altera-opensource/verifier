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

package com.intel.bkp.command.responses.spdm;

import com.intel.bkp.utils.ByteSwap;
import com.intel.bkp.utils.ByteSwapOrder;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import static com.intel.bkp.command.responses.spdm.SpdmCertificateResponseBuilder.CERT_CHAIN_HASH_LEN;
import static com.intel.bkp.command.responses.spdm.SpdmCertificateResponseBuilder.TOTAL_LEN_OF_THIS_STRUCTURE_BASE;
import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

class SpdmCertificateResponseBuilderTest {

    private static final byte[] CERTIFICATE_CHAIN = {1, 2, 3, 4};
    private static final byte[] CERTIFICATE_CHAIN_HASH = new byte[CERT_CHAIN_HASH_LEN];

    private SpdmCertificateResponseBuilder sut;

    @BeforeEach
    void setUp() {
        sut = new SpdmCertificateResponseBuilder();
    }

    @Test
    void withCertificateChain_UpdatesTotalLen() {
        // given
        final short expectedTotalLen = (short) (TOTAL_LEN_OF_THIS_STRUCTURE_BASE + CERTIFICATE_CHAIN.length);

        // when
        sut.withCertificateChain(CERTIFICATE_CHAIN);

        // then
        assertEquals(expectedTotalLen, sut.getTotalLenOfThisStructure());
    }

    @Test
    void withTooLargeCertificateChain_Throws() {
        // when-then
        assertThrows(RuntimeException.class, () -> sut.withCertificateChain(new byte[Short.MAX_VALUE]));
    }

    @Test
    void build_parse_Success() {
        // given
        final short expectedTotalLen = (short) (TOTAL_LEN_OF_THIS_STRUCTURE_BASE + CERTIFICATE_CHAIN.length);
        sut.withCertificateChain(CERTIFICATE_CHAIN);
        sut.withCertificateChainHash(CERTIFICATE_CHAIN_HASH);

        // when
        final SpdmCertificateResponse result = sut.build();
        final SpdmCertificateResponseBuilder parsed = sut.parse(result.array());

        // then
        assertArrayEquals(CERTIFICATE_CHAIN, result.getCertificateChain());
        assertArrayEquals(CERTIFICATE_CHAIN, parsed.getCertificateChain());
        assertArrayEquals(CERTIFICATE_CHAIN_HASH, result.getCertificateChainHash());
        assertArrayEquals(CERTIFICATE_CHAIN_HASH, parsed.getCertificateChainHash());
        assertEquals(expectedTotalLen,
            ByteSwap.getSwappedShort(result.getTotalLenOfThisStructure(), ByteSwapOrder.L2B));
        assertEquals(expectedTotalLen, parsed.getTotalLenOfThisStructure());
    }

    @Test
    void parse_InvalidTotalLen_Throws() {
        // when-then
        assertThrows(RuntimeException.class,
            () -> sut.parse(new byte[TOTAL_LEN_OF_THIS_STRUCTURE_BASE]));
    }
}

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

package com.intel.bkp.verifier.protocol.spdm.model;

import com.intel.bkp.crypto.constants.CryptoConstants;
import com.intel.bkp.protocol.spdm.jna.model.SpdmGetDigestResult;
import org.apache.commons.lang3.ArrayUtils;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertIterableEquals;

class SpdmDigestResponseBuilderTest {

    private static final int SLOT_2 = 0x02;
    private static final int SLOT_3 = 0x03;
    private static final byte SLOT_SET_2 = (byte) Math.pow(2, SLOT_2);
    private static final byte SLOT_SET_3 = (byte) Math.pow(2, SLOT_3);
    private static final byte[] SLOT_MASK = new byte[]{(byte) (SLOT_SET_2 | SLOT_SET_3)};

    private static final int HASH_ALG_LEN = CryptoConstants.SHA384_LEN;
    private static final byte[] DIGEST_2 = new byte[HASH_ALG_LEN];
    private static final byte[] DIGEST_3 = new byte[HASH_ALG_LEN];
    private static final byte[] DIGEST;

    static {
        // dummy data
        DIGEST_2[0] = (byte) 0x02;
        DIGEST_2[1] = (byte) 0x02;

        DIGEST_3[4] = (byte) 0x03;
        DIGEST_3[5] = (byte) 0x03;

        DIGEST = ArrayUtils.addAll(DIGEST_2, DIGEST_3);
    }

    private SpdmDigestResponseBuilder sut = new SpdmDigestResponseBuilder();

    @Test
    void parse_build_Success() {
        // given
        final SpdmGetDigestResult getDigestResult = new SpdmGetDigestResult(SLOT_MASK, DIGEST, HASH_ALG_LEN);

        // when
        final SpdmDigestResponse result = sut.parse(getDigestResult).build();

        // then
        assertEquals(2, result.getDigestMap().size());
        assertArrayEquals(DIGEST_2, result.getDigestMap().get(SLOT_2));
        assertArrayEquals(DIGEST_3, result.getDigestMap().get(SLOT_3));
        assertIterableEquals(List.of(SLOT_2, SLOT_3), result.getFilledSlots());
    }
}

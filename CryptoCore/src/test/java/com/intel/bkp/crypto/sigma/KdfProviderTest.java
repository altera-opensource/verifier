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

package com.intel.bkp.crypto.sigma;

import com.intel.bkp.crypto.exceptions.HMacProviderException;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;

public class KdfProviderTest {

    private static final byte[] MASTER_KEY = new byte[] { 1, 2, 3, 4, 5 };

    @Test
    public void derivePMK_ReturnValidObject() throws HMacProviderException {
        // when
        final byte[] result = KdfProvider.derivePMK(MASTER_KEY);

        // then
        assertNotNull(result);
        assertEquals(KdfProvider.PMK_OUTPUT_KEY_LEN, result.length);
    }

    @Test
    public void deriveSEK_ReturnValidObject() throws HMacProviderException {
        // when
        final byte[] result = KdfProvider.deriveSEK(MASTER_KEY);

        // then
        assertNotNull(result);
        assertEquals(KdfProvider.SEK_SMK_OUTPUT_KEY_LEN, result.length);
    }

    @Test
    public void deriveSMK_ReturnValidObject() throws HMacProviderException {
        // when
        final byte[] result = KdfProvider.deriveSMK(MASTER_KEY);

        // then
        assertNotNull(result);
        assertEquals(KdfProvider.SEK_SMK_OUTPUT_KEY_LEN, result.length);
    }

    @Test
    public void getLabel_ReturnValidObject() {
        // given
        for (KdfProvider.KdfDetails detail : KdfProvider.KdfDetails.values()) {
            final byte[] label = detail.getLabel();
            final int len = detail.getLen();

            assertEquals(len, label.length);
        }
    }
}

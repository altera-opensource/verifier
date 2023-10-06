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

package com.intel.bkp.fpgacerts.url.filename;

import com.intel.bkp.fpgacerts.model.Family;
import com.intel.bkp.fpgacerts.url.params.RimParams;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;

class XrimDataNameProviderTest {

    private static final String EXPECTED_SKI = "41SSZwl66ctC-wuR6nz5ggpzhTY";
    private static final String EXPECTED_FAMILY_NAME = "agilex";
    private static final RimParams DATA_PARAMS = new RimParams(EXPECTED_SKI, Family.AGILEX.getFamilyName());

    private static final XrimDataNameProvider sut = new XrimDataNameProvider(DATA_PARAMS);

    @Test
    void getFileNameParameters_Success() {
        // when
        final Object[] params = sut.getFileNameParameters();

        // then
        assertEquals(2, params.length);
        assertEquals(EXPECTED_FAMILY_NAME, params[0]);
        assertEquals(EXPECTED_SKI, params[1]);
    }
}

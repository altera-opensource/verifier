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

package com.intel.bkp.verifier.model.dice;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

class MaskedVendorInfoFactoryTest {

    @Test
    void get_WithMaskedVendorInfo() {
        // given
        Object obj = new MaskedVendorInfo("ABC");

        // when
        final MaskedVendorInfo result = MaskedVendorInfoFactory.get(obj);

        // then
        Assertions.assertEquals(obj, result);
    }

    @Test
    void get_WithString() {
        // given
        Object obj = "ABC";

        // when
        final MaskedVendorInfo result = MaskedVendorInfoFactory.get(obj);

        // then
        Assertions.assertEquals("ABC", result.getVendorInfo());
        Assertions.assertNull(result.getVendorInfoMask());
    }

    @Test
    void get_WithOther() {
        // given
        Object obj = 1;

        // when
        final MaskedVendorInfo result = MaskedVendorInfoFactory.get(obj);

        // then
        Assertions.assertEquals("", result.getVendorInfo());
        Assertions.assertNull(result.getVendorInfoMask());
    }
}

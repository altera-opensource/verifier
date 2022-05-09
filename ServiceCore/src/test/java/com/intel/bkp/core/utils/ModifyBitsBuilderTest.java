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

package com.intel.bkp.core.utils;

import com.intel.bkp.core.psgcertificate.model.PsgPermissions;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

public class ModifyBitsBuilderTest {

    @Test
    void build_With_AllSet_ReturnsAllSet() {
        // given
        final ModifyBitsBuilder builder = ModifyBitsBuilder.fromAll();

        // when
        final int build = builder.build();

        // then
        Assertions.assertEquals("11111111111111111111111111111111", builder.toString());
        Assertions.assertEquals(-1, build);
    }

    @Test
    void build_With_NoneSet_ReturnsAllUnset() {
        // given
        final ModifyBitsBuilder builder = ModifyBitsBuilder.fromNone();

        // when
        final int build = builder.build();

        // then
        Assertions.assertEquals("00000000000000000000000000000000", builder.toString());
        Assertions.assertEquals(0, build);
    }

    @Test
    void build_With_NoneSetAndSetSinglePermission_SetOnlySelectedBits() {
        // given
        final ModifyBitsBuilder builder = ModifyBitsBuilder.fromNone();

        // when
        builder.set(PsgPermissions.SIGN_CERT.getBitPosition());
        final int build = builder.build();

        // then
        Assertions.assertEquals("00000000000000010000000000000000", builder.toString());
        Assertions.assertEquals(65536, build);
    }

    @Test
    void build_With_NoneSetAndSetMultiplePermissions_SetOnlySelectedBits() {
        // given
        final ModifyBitsBuilder builder = ModifyBitsBuilder.fromNone();

        // when
        builder.set(PsgPermissions.SIGN_CERT.getBitPosition()).set(PsgPermissions.SIGN_BKP_DH.getBitPosition());
        final int build = builder.build();

        // then
        Assertions.assertEquals("00000000000000010000000000010000", builder.toString());
        Assertions.assertEquals(65552, build);
    }

    @Test
    void build_With_AllSetAndUnSetMultiplePermissions_UnsetOnlySelectedBits() {
        // given
        final ModifyBitsBuilder builder = ModifyBitsBuilder.fromAll();

        // when
        builder.unset(PsgPermissions.SIGN_CERT.getBitPosition()).unset(PsgPermissions.SIGN_BKP_DH.getBitPosition());
        final int build = builder.build();

        // then
        Assertions.assertEquals("11111111111111101111111111101111", builder.toString());
        Assertions.assertEquals(-65553, build);
    }
}

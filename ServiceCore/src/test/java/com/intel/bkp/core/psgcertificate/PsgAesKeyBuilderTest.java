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

package com.intel.bkp.core.psgcertificate;

import com.intel.bkp.core.endianess.EndianessActor;
import com.intel.bkp.core.psgcertificate.enumerations.KeyWrappingType;
import com.intel.bkp.core.psgcertificate.enumerations.StorageType;
import org.apache.commons.io.IOUtils;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

import java.io.IOException;

import static com.intel.bkp.utils.HexConverter.toHex;

class PsgAesKeyBuilderTest {

    private static final String AES_KEY_E2E = "3022E09098452FF5521674B193D0FB50D64D92D8977461F403161D86CEDEFE12";
    private static final String AES_KEY_CUSTOM = "9F4AC374FFE4226BFDF36F52B9B85603468634BD21A20E50AF8BBE9B1C233226";

    @Test
    void parse_WithActualData_Success() throws Exception {
        // given
        final byte[] aesContent = loadExampleAesKey("signed_aes.ccert");

        // when
        PsgAesKeyBuilder builder = new PsgAesKeyBuilder()
            .withActor(EndianessActor.FIRMWARE)
            .parse(aesContent);

        // then
        commonAssert(aesContent, builder, StorageType.PUFSS, KeyWrappingType.IID);
        Assertions.assertEquals(AES_KEY_E2E, toHex(builder.getUserAesRootKey()));
    }

    @Test
    void parse_WithActualData_withBBram_Success() throws Exception {
        // given
        final byte[] aesContent = loadExampleAesKey("signed_bbram_aes.ccert");

        // when
        PsgAesKeyBuilder builder = new PsgAesKeyBuilder()
            .withActor(EndianessActor.FIRMWARE)
            .parse(aesContent);

        // then
        commonAssert(aesContent, builder, StorageType.BBRAM, KeyWrappingType.NOWRAP);
        Assertions.assertEquals(AES_KEY_E2E, toHex(builder.getUserAesRootKey()));
    }

    @Test
    void parse_WithActualData_withEfuse_Success() throws Exception {
        // given
        final byte[] aesContent = loadExampleAesKey("signed_efuse_dimk_wrapped_aes.ccert");

        // when
        PsgAesKeyBuilder builder = new PsgAesKeyBuilder()
            .withActor(EndianessActor.FIRMWARE)
            .parse(aesContent);

        // then
        commonAssert(aesContent, builder, StorageType.EFUSES, KeyWrappingType.INTERNAL);
        Assertions.assertEquals(AES_KEY_E2E, toHex(builder.getUserAesRootKey()));
    }

    @Test
    void parse_WithActualData_withEfuseNotFromE2eTests_Success() throws Exception {
        // given
        final byte[] aesContent = loadExampleAesKey("signed_efuse_dimk_wrapped_aes_wrong.ccert");

        // when
        PsgAesKeyBuilder builder = new PsgAesKeyBuilder()
            .withActor(EndianessActor.FIRMWARE)
            .parse(aesContent);

        // then
        commonAssert(aesContent, builder, StorageType.EFUSES, KeyWrappingType.INTERNAL);

        Assertions.assertEquals(AES_KEY_CUSTOM, toHex(builder.getUserAesRootKey()));
    }

    private byte[] loadExampleAesKey(String filename) throws IOException {
        return IOUtils.toByteArray(PsgAesKeyBuilderTest.class.getResourceAsStream("/testfiles/" + filename));
    }

    private void commonAssert(byte[] content, PsgAesKeyBuilder builder, StorageType storage, KeyWrappingType keyType) {
        Assertions.assertNotNull(builder);
        Assertions.assertEquals(storage, builder.getStorageType());
        Assertions.assertEquals(keyType, builder.getKeyWrappingType());

        final String expected = toHex(content);
        final String actual = toHex(builder.build().array());
        Assertions.assertEquals(expected, actual);
    }
}

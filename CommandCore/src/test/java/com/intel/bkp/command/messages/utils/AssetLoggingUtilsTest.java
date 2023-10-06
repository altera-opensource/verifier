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

package com.intel.bkp.command.messages.utils;

import org.apache.commons.lang3.StringUtils;
import org.junit.jupiter.api.Test;

import static com.intel.bkp.command.messages.utils.AssetLoggingUtils.COULD_NOT_PRINT;
import static com.intel.bkp.command.messages.utils.AssetLoggingUtils.SHA384_LEN;
import static org.junit.jupiter.api.Assertions.assertEquals;

class AssetLoggingUtilsTest {

    @Test
    void getHiddenAsset_Success() {
        // given
        String asset = StringUtils.repeat("00", SHA384_LEN);

        // when
        String result = AssetLoggingUtils.getHiddenAsset(asset);

        // then
        assertEquals("000000000000000000000000...<hidden SHA384 bytes>...000000000000000000000000", result);
    }

    @Test
    void getHiddenAsset_WithTooShortAsset() {
        // given
        String asset = "abcd";

        // when
        String result = AssetLoggingUtils.getHiddenAsset(asset);

        // then
        assertEquals(COULD_NOT_PRINT, result);
    }
}

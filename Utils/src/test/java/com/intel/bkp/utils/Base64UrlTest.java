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

package com.intel.bkp.utils;

import org.junit.jupiter.api.Test;

import static com.intel.bkp.utils.HexConverter.fromHex;
import static org.junit.jupiter.api.Assertions.assertEquals;

class Base64UrlTest {

    private static final byte[] DATA = fromHex("0102030405");
    private static final byte[] DATA_2 = fromHex("01020304");
    private static final String DATA_IN_BASE64URL = "AQIDBAU=";
    private static final String DATA_IN_BASE64URL_2 = "AQIDBA==";
    private static final String DATA_IN_BASE64URL_NO_PADDING = "AQIDBAU";
    private static final String DATA_IN_BASE64URL_NO_PADDING_2 = "AQIDBA";

    @Test
    void encodeWithoutPadding_Success() {
        assertEquals(DATA_IN_BASE64URL_NO_PADDING, Base64Url.encodeWithoutPadding(DATA));
    }

    @Test
    void encodeWithoutPadding_WithDoublePadding_Success() {
        assertEquals(DATA_IN_BASE64URL_NO_PADDING_2, Base64Url.encodeWithoutPadding(DATA_2));
    }

    @Test
    void encode_Success() {
        assertEquals(DATA_IN_BASE64URL, Base64Url.encode(DATA));
    }

    @Test
    void encode_WithDoublePadding_Success() {
        assertEquals(DATA_IN_BASE64URL_2, Base64Url.encode(DATA_2));
    }
}

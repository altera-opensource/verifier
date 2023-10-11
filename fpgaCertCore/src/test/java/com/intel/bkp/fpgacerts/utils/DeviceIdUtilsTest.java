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

package com.intel.bkp.fpgacerts.utils;

import org.junit.jupiter.api.Test;

import java.math.BigInteger;

import static com.intel.bkp.utils.HexConverter.toHex;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;

class DeviceIdUtilsTest {

    private static final String DEVICE_ID_NEGATIVE_VALUE = "AEEE56B0DA843959";
    private static final String DEVICE_ID_POSITIVE_VALUE = "3E95DD61F4D5B8D6";
    private static final String DEVICE_ID_VALUE_WITH_0000 = "0000DD61F4D5B8D6";

    @Test
    void getS10CertificateSerialNumber_WithNegativeValue_Success() {
        // when
        final BigInteger bigInteger = DeviceIdUtils.getS10CertificateSerialNumber(DEVICE_ID_NEGATIVE_VALUE);
        final String actual = toHex(bigInteger.toByteArray());

        // then
        assertNotNull(bigInteger);
        assertEquals((Long.BYTES + 1) * 2, actual.length());
        assertEquals("01" + DEVICE_ID_NEGATIVE_VALUE, actual);
    }

    @Test
    void getS10CertificateSerialNumber_WithPositiveValue_Success() {
        // when
        final BigInteger bigInteger = DeviceIdUtils.getS10CertificateSerialNumber(DEVICE_ID_POSITIVE_VALUE);
        final String actual = toHex(bigInteger.toByteArray());
        // then
        assertNotNull(bigInteger);
        assertEquals((Long.BYTES + 1) * 2, actual.length());
        assertEquals("01" + DEVICE_ID_POSITIVE_VALUE, toHex(bigInteger.toByteArray()));
    }

    @Test
    void getS10CertificateSerialNumber_With0000Value_Success() {
        // when
        final BigInteger bigInteger = DeviceIdUtils.getS10CertificateSerialNumber(DEVICE_ID_VALUE_WITH_0000);
        final String actual = toHex(bigInteger.toByteArray());

        // then
        assertNotNull(bigInteger);
        assertEquals((Long.BYTES + 1) * 2, actual.length());
        assertEquals("01" + DEVICE_ID_VALUE_WITH_0000, actual);
    }
}

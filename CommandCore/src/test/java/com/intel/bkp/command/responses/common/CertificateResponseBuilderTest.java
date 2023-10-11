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

package com.intel.bkp.command.responses.common;

import com.intel.bkp.utils.exceptions.ByteBufferSafeException;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import static com.intel.bkp.utils.HexConverter.fromHex;
import static com.intel.bkp.utils.HexConverter.toHex;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class CertificateResponseBuilderTest {

    private static final String CERTIFICATE_PROCESS_STATUS_OK = "00000000";
    private static final String CERTIFICATE_PROCESS_STATUS_FAIL = "00000001";
    private static final String DATA = "0102030405060708";

    private CertificateResponseBuilder sut;

    @BeforeEach
    void setUp() {
        sut = new CertificateResponseBuilder();
    }

    @Test
    public void parse_build_ReturnValidObject() {
        // when
        final CertificateResponse result = sut
            .parse(fromHex(CERTIFICATE_PROCESS_STATUS_OK + DATA))
            .build();

        // then
        assertTrue(result.processCompleted());
        assertEquals(DATA, toHex(result.getResponseData()));
    }

    @Test
    public void parse_build_NoData_ReturnValidObject() {
        // when
        final CertificateResponse result = sut
            .parse(fromHex(CERTIFICATE_PROCESS_STATUS_OK))
            .build();

        // then
        assertTrue(result.processCompleted());
        assertEquals("", toHex(result.getResponseData()));
    }

    @Test
    public void parse_build_CertificateProcessFailed() {
        // when
        final CertificateResponse result = sut
            .parse(fromHex(CERTIFICATE_PROCESS_STATUS_FAIL))
            .build();

        // then
        assertFalse(result.processCompleted());
    }

    @Test
    public void parse_NoCertProcessStatus_Throws() {
        // when-then
        assertThrows(ByteBufferSafeException.class, () -> sut.parse(new byte[0]));
    }
}

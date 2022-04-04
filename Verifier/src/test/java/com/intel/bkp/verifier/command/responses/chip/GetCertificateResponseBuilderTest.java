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

package com.intel.bkp.verifier.command.responses.chip;

import com.intel.bkp.core.command.model.CertificateRequestType;
import com.intel.bkp.utils.exceptions.ByteBufferSafeException;
import com.intel.bkp.verifier.exceptions.SigmaException;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

import java.nio.ByteBuffer;

import static com.intel.bkp.utils.HexConverter.fromHex;
import static com.intel.bkp.utils.HexConverter.toHex;

class GetCertificateResponseBuilderTest {

    private static final String CERT_TYPE = "04000000";
    private static final String INCORRECT_CERT_TYPE = "03000000";
    private static final String DATA = "AABBCCDD";

    private GetCertificateResponseBuilder sut = new GetCertificateResponseBuilder();

    @Test
    public void parse_build_ReturnValidObject() {
        // when
        final GetCertificateResponse result = sut
            .parse(fromHex(CERT_TYPE + DATA))
            .build();

        // then
        Assertions.assertEquals(CertificateRequestType.DEVICE_ID_ENROLLMENT, result.getCertificateTypeValue());
        Assertions.assertEquals(DATA, toHex(result.getCertificateBlob()));
    }

    @Test
    public void parse_IncorrectCertificateType_Throws() {
        // given
        final byte[] response = fromHex(INCORRECT_CERT_TYPE + DATA);
        final String expectedMessage = String.format("Unknown certificate type: %s", INCORRECT_CERT_TYPE);

        // when-then
        final var ex = Assertions.assertThrows(SigmaException.class, () -> sut.parse(response));

        // then
        Assertions.assertEquals(expectedMessage, ex.getMessage());
    }

    @Test
    public void parse_NoData_Throws() {
        // when-then
        Assertions.assertThrows(ByteBufferSafeException.class, () -> sut.parse(new byte[0]));
    }

    @Test
    public void parse_NoCertificate_Throws() {
        // when-then
        Assertions.assertThrows(SigmaException.class, () -> sut.parse(fromHex(CERT_TYPE)));
    }

    @Test
    public void parse_DataMaxSize_DoesNotThrow() {
        // given
        byte[] response = ByteBuffer.allocate(4096).put(fromHex(CERT_TYPE)).array();

        // when-then
        Assertions.assertDoesNotThrow(() -> sut.parse(response));
    }

    @Test
    public void parse_TooMuchData_Throws() {
        // given
        byte[] response = ByteBuffer.allocate(4097).put(fromHex(CERT_TYPE)).array();

        // when-then
        Assertions.assertThrows(SigmaException.class, () -> sut.parse(response));
    }
}

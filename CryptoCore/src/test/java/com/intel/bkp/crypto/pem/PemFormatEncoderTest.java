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

package com.intel.bkp.crypto.pem;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

import static com.intel.bkp.crypto.pem.PemFormatHeader.CRL;
import static com.intel.bkp.crypto.pem.PemFormatHeader.CSR;
import static com.intel.bkp.crypto.pem.PemFormatHeader.PUBLIC_KEY;

class PemFormatEncoderTest {

    private static final byte[] EXPECTED_BYTES = new byte[]{0, 1, 2, 3, 4};

    @Test
    public void encodeCertificateRequest_ShouldEncodeCertificateRequest() {
        // given
        byte[] content = "test".getBytes();
        String output = String.format("%s%s%s", CSR.getBegin(), "\ndGVzdA==\n", CSR.getEnd());

        // when
        String encoded = PemFormatEncoder.encode(CSR, content);

        // then
        Assertions.assertEquals(output, encoded);
    }

    @Test
    public void encodeCrlRequest_ShouldEncodeCrlRequest() {
        // given
        byte[] content = "test".getBytes();
        String output = String.format("%s%s%s", CRL.getBegin(), "\ndGVzdA==\n", CRL.getEnd());

        // when
        String encoded = PemFormatEncoder.encode(CRL, content);

        // then
        Assertions.assertEquals(output, encoded);
    }


    @Test
    void encodePublicKey_SuccessfullyEncodesData() {
        // when
        String result = PemFormatEncoder.encode(PUBLIC_KEY, EXPECTED_BYTES);

        // then
        Assertions.assertNotNull(result);
        Assertions.assertTrue(result.contains(PUBLIC_KEY.getBegin()));
        Assertions.assertTrue(result.contains(PUBLIC_KEY.getEnd()));
    }

}

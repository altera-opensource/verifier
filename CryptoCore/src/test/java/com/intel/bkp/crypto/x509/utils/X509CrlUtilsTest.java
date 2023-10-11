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

package com.intel.bkp.crypto.x509.utils;

import com.intel.bkp.test.FileUtils;
import com.intel.bkp.test.enumeration.ResourceDir;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.junit.jupiter.MockitoExtension;

import java.math.BigInteger;
import java.security.cert.X509CRL;
import java.util.List;

import static com.intel.bkp.crypto.x509.parsing.X509CrlParser.pemToX509Crl;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

@ExtendWith(MockitoExtension.class)
class X509CrlUtilsTest {

    private static final String CRL_WITH_REVOKED_SERIAL_NUMBERS = "IPCSSigningCA.crl";
    private static final String REVOKED_SERIAL_NUMBER = "01099BDF89CA6BB908";
    private static final int REVOKED_SERIAL_NUMBERS_COUNT = 37;
    private static final BigInteger CRL_NUMBER = new BigInteger("135");

    private static String crlInPem;
    private static X509CRL crl;

    @BeforeAll
    public static void beforeClass() throws Exception {
        crlInPem = FileUtils.loadFile(ResourceDir.CERTS, CRL_WITH_REVOKED_SERIAL_NUMBERS);
        crl = pemToX509Crl(crlInPem);
    }

    @Test
    void isRevoked_RevokedSerialNumber_ReturnsTrue() {
        // given
        final BigInteger revokedSerialNumber = new BigInteger(REVOKED_SERIAL_NUMBER, 16);

        // when-then
        assertTrue(X509CrlUtils.isRevoked(crl, revokedSerialNumber));
    }

    @Test
    void isRevoked_NotRevokedSerialNumber_ReturnsFalse() {
        // given
        final BigInteger notRevokedSerialNumber = BigInteger.ONE;

        // when-then
        assertFalse(X509CrlUtils.isRevoked(crl, notRevokedSerialNumber));
    }

    @Test
    void getRevokedSerialNumbersInHex_Success() {
        // when
        final List<String> result = X509CrlUtils.getRevokedSerialNumbersInHex(crl);

        // then
        assertEquals(REVOKED_SERIAL_NUMBERS_COUNT, result.size());
        assertTrue(result.contains(REVOKED_SERIAL_NUMBER));
    }

    @Test
    void getCrlNumber_Success() {
        // when
        final BigInteger crlNumber = X509CrlUtils.getCrlNumber(crl);

        // then
        assertEquals(CRL_NUMBER, crlNumber);
    }

    @Test
    void toPem_Success() throws Exception {
        // when
        final String result = X509CrlUtils.toPem(crl);

        // then
        assertEquals(crlInPem, result);
    }
}

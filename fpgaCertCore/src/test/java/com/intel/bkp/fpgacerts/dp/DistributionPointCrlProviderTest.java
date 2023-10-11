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

package com.intel.bkp.fpgacerts.dp;

import com.intel.bkp.crypto.exceptions.X509CrlParsingException;
import com.intel.bkp.crypto.x509.parsing.X509CrlParser;
import com.intel.bkp.fpgacerts.exceptions.X509Exception;
import lombok.SneakyThrows;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.MockedStatic;
import org.mockito.junit.jupiter.MockitoExtension;

import java.security.cert.X509CRL;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.Mockito.mockStatic;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class DistributionPointCrlProviderTest {

    private static final String URL = "URL";
    private static final byte[] MOCKED_CRL_BYTES = new byte[]{0x01, 0x02, 0x03};

    private static MockedStatic<X509CrlParser> x509CrlParserMockStatic;

    @Mock
    private X509CRL crl;

    @Mock
    private DistributionPointConnector connector;

    private DistributionPointCrlProvider sut;

    @BeforeAll
    public static void prepareStaticMock() {
        x509CrlParserMockStatic = mockStatic(X509CrlParser.class);
    }

    @AfterAll
    public static void closeStaticMock() {
        x509CrlParserMockStatic.close();
    }

    @BeforeEach
    void prepareSut() {
        sut = new DistributionPointCrlProvider(connector);
    }

    @Test
    void getCrl_Success() {
        // given
        mockDistributionPointConnector();
        mockParsingSuccess();

        // when
        final X509CRL result = sut.getCrl(URL);

        // then
        assertEquals(crl, result);
    }

    @Test
    void getCrl_CrlParsingFails_Throws() {
        // given
        mockDistributionPointConnector();
        mockParsingFailure();

        // when
        assertThrows(X509Exception.class, () -> sut.getCrl(URL));
    }

    private void mockDistributionPointConnector() {
        when(connector.getBytes(URL)).thenReturn(MOCKED_CRL_BYTES);
    }

    @SneakyThrows
    private void mockParsingSuccess() {
        when(X509CrlParser.toX509Crl(MOCKED_CRL_BYTES)).thenReturn(crl);
    }

    @SneakyThrows
    private void mockParsingFailure() {
        when(X509CrlParser.toX509Crl(MOCKED_CRL_BYTES)).thenThrow(new X509CrlParsingException("", null));
    }
}

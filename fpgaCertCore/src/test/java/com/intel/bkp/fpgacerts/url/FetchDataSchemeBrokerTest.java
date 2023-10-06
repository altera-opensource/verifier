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

package com.intel.bkp.fpgacerts.url;

import com.intel.bkp.fpgacerts.dp.DistributionPointConnector;
import com.intel.bkp.fpgacerts.exceptions.DataPathException;
import com.intel.bkp.fpgacerts.utils.LocalFileLoader;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.NullAndEmptySource;
import org.junit.jupiter.params.provider.ValueSource;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.util.Optional;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.mockStatic;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class FetchDataSchemeBrokerTest {

    private static final Optional<byte[]> EXPECTED = Optional.of(new byte[]{1, 2, 3});

    @Mock
    private DistributionPointConnector distributionPointConnector;

    @ParameterizedTest
    @ValueSource(strings = {
        "https://localhost/test.txt",
        "HTTPS://localhost/test.txt",
        "http://localhost/test.txt",
        "HTTP://localhost/test.txt"
    })
    void fetchData_WithValidRemoteUrls_Success(String url) {
        // given
        when(distributionPointConnector.tryGetBytes(anyString())).thenReturn(EXPECTED);

        // when
        final Optional<byte[]> response;
        try (var loaderMockStatic = mockStatic(LocalFileLoader.class)) {
            loaderMockStatic
                .when(() -> LocalFileLoader.load(any()))
                .thenReturn(EXPECTED);
            response = FetchDataSchemeBroker.fetchData(url, distributionPointConnector);
            loaderMockStatic.verifyNoInteractions();
        }

        // then
        assertEquals(EXPECTED, response);
        verify(distributionPointConnector).tryGetBytes(anyString());
    }

    @ParameterizedTest
    @ValueSource(strings = {
        "file:///tmp/file.txt",
        "file://tmp/file.txt",
        "file:/tmp/file.txt",
        "FILE:///tmp/file.txt"
    })
    void fetchData_WithValidLocalUrls_Success(String url) {
        // when
        final Optional<byte[]> response;
        try (var loaderMockStatic = mockStatic(LocalFileLoader.class)) {
            loaderMockStatic
                .when(() -> LocalFileLoader.load(any()))
                .thenReturn(EXPECTED);
            response = FetchDataSchemeBroker.fetchData(url, distributionPointConnector);
        }

        // then
        assertEquals(EXPECTED, response);
        verify(distributionPointConnector, never()).tryGetBytes(anyString());
    }

    @ParameterizedTest
    @ValueSource(strings = {
        "NOT_URL",
        "ftp://localhost/test.txt",
        "ssh://localhost/test.txt",
    })
    void fetchData_WithNotSupportedUrls_ReturnsEmpty(String url) {
        // given
        final Optional<byte[]> response;

        // when
        try (var loaderMockStatic = mockStatic(LocalFileLoader.class)) {
            response = FetchDataSchemeBroker.fetchData(url, distributionPointConnector);
            loaderMockStatic.verifyNoInteractions();
        }

        // then
        assertEquals(Optional.empty(), response);
        verify(distributionPointConnector, never()).tryGetBytes(anyString());
    }

    @ParameterizedTest
    @NullAndEmptySource
    void fetchData_WithEmptyUrl_ReturnsEmpty(String url) {
        // when-then
        assertThrows(DataPathException.class,
            () -> FetchDataSchemeBroker.fetchData(url, distributionPointConnector));
    }
}

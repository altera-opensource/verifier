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

package com.intel.bkp.verifier.protocol.spdm.jna;

import com.intel.bkp.protocol.spdm.jna.model.LibSpdmLibraryWrapper;
import com.intel.bkp.verifier.model.LibConfig;
import com.intel.bkp.verifier.model.LibSpdmParams;
import com.intel.bkp.verifier.service.certificate.AppContext;
import com.sun.jna.Native;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.MockedStatic;
import org.mockito.junit.jupiter.MockitoExtension;

import static org.junit.jupiter.api.Assertions.assertSame;
import static org.mockito.Mockito.mockStatic;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class LibSpdmLibraryWrapperImplTest {

    private static final String LIBSPDM_FAKE_PATH = "FAKE PATH";
    private static MockedStatic<AppContext> appContextMockedStatic;
    private static MockedStatic<Native> nativeMockedStatic;

    @Mock
    private AppContext appContextMock;
    @Mock
    private LibConfig libConfigMock;
    @Mock
    private LibSpdmParams libSpdmParamsMock;
    @Mock
    private LibSpdmLibraryWrapper wrapperMock;

    @BeforeAll
    public static void prepareStaticMock() {
        appContextMockedStatic = mockStatic(AppContext.class);
        nativeMockedStatic = mockStatic(Native.class);
    }

    @AfterAll
    public static void closeStaticMock() {
        appContextMockedStatic.close();
        nativeMockedStatic.close();
    }

    @BeforeEach
    void setUp() {
        when(AppContext.instance()).thenReturn(appContextMock);
        when(appContextMock.getLibConfig()).thenReturn(libConfigMock);
        when(libConfigMock.getLibSpdmParams()).thenReturn(libSpdmParamsMock);
        when(libSpdmParamsMock.getWrapperLibraryPath()).thenReturn(LIBSPDM_FAKE_PATH);
    }

    @Test
    void getInstance() {
        // given
        when(Native.load(LIBSPDM_FAKE_PATH, LibSpdmLibraryWrapper.class)).thenReturn(wrapperMock);

        // when
        final LibSpdmLibraryWrapper result = LibSpdmLibraryWrapperImpl.getInstance();
        final LibSpdmLibraryWrapper resultSecond = LibSpdmLibraryWrapperImpl.getInstance();

        // then
        assertSame(wrapperMock, result);
        assertSame(wrapperMock, resultSecond);
    }
}

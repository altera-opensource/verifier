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

package com.intel.bkp.verifier.service.spdm;

import com.intel.bkp.verifier.jna.LibSpdmLibraryWrapperImpl;
import com.intel.bkp.verifier.jna.model.Uint32;
import com.intel.bkp.verifier.jna.model.Uint8;
import com.intel.bkp.verifier.model.LibConfig;
import com.intel.bkp.verifier.model.LibSpdmParams;
import com.intel.bkp.verifier.service.certificate.AppContext;
import com.sun.jna.Pointer;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.MockedStatic;
import org.mockito.junit.jupiter.MockitoExtension;

import static com.intel.bkp.verifier.jna.model.LibSpdmDataType.LIBSPDM_DATA_BASE_ASYM_ALGO;
import static com.intel.bkp.verifier.jna.model.LibSpdmDataType.LIBSPDM_DATA_BASE_HASH_ALGO;
import static com.intel.bkp.verifier.jna.model.LibSpdmDataType.LIBSPDM_DATA_CAPABILITY_CT_EXPONENT;
import static com.intel.bkp.verifier.jna.model.LibSpdmDataType.LIBSPDM_DATA_CAPABILITY_FLAGS;
import static com.intel.bkp.verifier.jna.model.LibSpdmDataType.LIBSPDM_DATA_MEASUREMENT_SPEC;
import static com.intel.bkp.verifier.jna.model.SpdmConstants.SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_ECDSA_ECC_NIST_P384;
import static com.intel.bkp.verifier.jna.model.SpdmConstants.SPDM_ALGORITHMS_BASE_HASH_ALGO_TPM_ALG_SHA_384;
import static com.intel.bkp.verifier.jna.model.SpdmConstants.SPDM_GET_CAPABILITIES_REQUEST_FLAGS_CERT_CAP;
import static com.intel.bkp.verifier.jna.model.SpdmConstants.SPDM_MEASUREMENT_BLOCK_HEADER_SPECIFICATION_DMTF;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mockStatic;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class SpdmParametersSetterTest {

    private static final int SPDM_CT_EXP = 0x04;

    private static MockedStatic<AppContext> appContextMockedStatic;
    private static MockedStatic<LibSpdmLibraryWrapperImpl> wrapperMockedStatic;

    @Mock
    private LibSpdmLibraryWrapperImpl.LibSpdmLibraryWrapper wrapperMock;

    @Mock
    private AppContext appContextMock;
    @Mock
    private LibConfig libConfigMock;
    @Mock
    private LibSpdmParams libSpdmParamsMock;
    @Mock
    private Pointer context;

    private final SpdmParametersSetter sut = new SpdmParametersSetter();

    @BeforeAll
    public static void prepareStaticMock() {
        appContextMockedStatic = mockStatic(AppContext.class);
        wrapperMockedStatic = mockStatic(LibSpdmLibraryWrapperImpl.class);
    }

    @AfterAll
    public static void closeStaticMock() {
        appContextMockedStatic.close();
        wrapperMockedStatic.close();
    }

    @BeforeEach
    void setUp() {
        when(AppContext.instance()).thenReturn(appContextMock);
        when(LibSpdmLibraryWrapperImpl.getInstance()).thenReturn(wrapperMock);
        when(appContextMock.getLibConfig()).thenReturn(libConfigMock);
        when(libConfigMock.getLibSpdmParams()).thenReturn(libSpdmParamsMock);
        when(libSpdmParamsMock.getCtExponent()).thenReturn(SPDM_CT_EXP);
    }

    @Test
    void setLibspdmParameters_Success() {
        // when
        sut.setLibspdmParameters(context);

        // then
        Assertions.assertAll(
            () -> verifyWrapperCallSetDataW8(LIBSPDM_DATA_CAPABILITY_CT_EXPONENT, SPDM_CT_EXP),
            () -> verifyWrapperCallSetDataW8(LIBSPDM_DATA_MEASUREMENT_SPEC,
                SPDM_MEASUREMENT_BLOCK_HEADER_SPECIFICATION_DMTF),

            () -> verifyWrapperCallSetDataW32(LIBSPDM_DATA_CAPABILITY_FLAGS,
                SPDM_GET_CAPABILITIES_REQUEST_FLAGS_CERT_CAP),
            () -> verifyWrapperCallSetDataW32(LIBSPDM_DATA_BASE_ASYM_ALGO,
                SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_ECDSA_ECC_NIST_P384),
            () -> verifyWrapperCallSetDataW32(LIBSPDM_DATA_BASE_HASH_ALGO,
                SPDM_ALGORITHMS_BASE_HASH_ALGO_TPM_ALG_SHA_384)
        );
    }

    private Long verifyWrapperCallSetDataW8(int parameter, int value) {
        return verify(wrapperMock).libspdm_set_data_w8(eq(context), eq(parameter), any(),
            eq(new Uint8(value)), eq(Uint8.NATIVE_SIZE));
    }

    private Long verifyWrapperCallSetDataW32(int parameter, int value) {
        return verify(wrapperMock).libspdm_set_data_w32(eq(context), eq(parameter), any(),
            eq(new Uint32(value)), eq(Uint32.NATIVE_SIZE));
    }
}

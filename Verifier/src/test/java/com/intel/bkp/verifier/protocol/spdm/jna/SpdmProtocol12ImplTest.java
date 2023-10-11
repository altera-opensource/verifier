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

import com.intel.bkp.crypto.constants.CryptoConstants;
import com.intel.bkp.protocol.spdm.jna.model.LibSpdmLibraryWrapper;
import com.intel.bkp.protocol.spdm.jna.model.NativeSize;
import com.intel.bkp.protocol.spdm.jna.model.SessionCallbacks;
import com.intel.bkp.protocol.spdm.jna.model.SpdmGetDigestResult;
import com.intel.bkp.protocol.spdm.jna.model.Uint8;
import com.intel.bkp.verifier.exceptions.VerifierRuntimeException;
import com.intel.bkp.verifier.model.LibConfig;
import com.intel.bkp.verifier.model.LibSpdmParams;
import com.intel.bkp.verifier.service.certificate.AppContext;
import com.sun.jna.Pointer;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.MockedStatic;
import org.mockito.Mockito;
import org.mockito.junit.jupiter.MockitoExtension;
import org.mockito.stubbing.Answer;

import java.nio.ByteBuffer;

import static com.intel.bkp.protocol.spdm.jna.model.SpdmConstants.LIBSPDM_STATUS_SUCCESS;
import static com.intel.bkp.protocol.spdm.jna.model.SpdmConstants.SPDM_GET_MEASUREMENTS_REQUEST_ATTRIBUTES_GENERATE_SIGNATURE;
import static com.intel.bkp.protocol.spdm.jna.model.SpdmConstants.SPDM_GET_MEASUREMENTS_REQUEST_ATTRIBUTES_RAW_BIT_STREAM_REQUESTED;
import static com.intel.bkp.utils.HexConverter.toHex;
import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyBoolean;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.doAnswer;
import static org.mockito.Mockito.doReturn;
import static org.mockito.Mockito.mockStatic;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class SpdmProtocol12ImplTest {

    private static final int SPDM_CT_EXP = 0x02;
    private static final int SLOT_ID = 0x02;
    private static final byte SLOT_MASK_GOOD = 4; // SLOT_ID of 0x02 means 3rd bit set in mask - 00000100 = 4
    private static final byte[] DIGEST = new byte[CryptoConstants.SHA384_LEN];

    static {
        // dummy data
        DIGEST[0] = (byte) 0x02;
        DIGEST[1] = (byte) 0x04;
    }

    private static MockedStatic<AppContext> appContextMockedStatic;

    @Mock
    private LibSpdmLibraryWrapper wrapperMock;
    @Mock
    private AppContext appContextMock;
    @Mock
    private LibConfig libConfigMock;
    @Mock
    private LibSpdmParams libSpdmParamsMock;

    private SpdmProtocol12Impl sut;

    @BeforeAll
    public static void prepareStaticMock() {
        appContextMockedStatic = mockStatic(AppContext.class);
    }

    @AfterAll
    public static void closeStaticMock() {
        appContextMockedStatic.close();
    }

    @BeforeEach
    void setUp() {
        when(AppContext.instance()).thenReturn(appContextMock);

        sut = new SpdmProtocol12Impl();
    }

    @Test
    void initializeLibrary_WrapperLibraryNotLoaded_Throws() {
        // given
        try (var wrapperMockedStatic = mockStatic(LibSpdmLibraryWrapperImpl.class)) {
            when(LibSpdmLibraryWrapperImpl.getInstance()).thenThrow(new UnsatisfiedLinkError());

            // when-then
            final VerifierRuntimeException ex =
                assertThrows(VerifierRuntimeException.class, sut::initializeLibrary);
            assertEquals("Failed to link SPDM Wrapper library.", ex.getMessage());
        }
    }

    @Test
    void getVersion_Success() throws Exception {
        // given
        try (var wrapperMockedStatic = mockStatic(LibSpdmLibraryWrapperImpl.class)) {
            mockWrapper();
            prepareLibConfig();
            prepareSpdmContextAndScratchBufferSize();

            final int expectedSpdmVersion = 0x01;

            when(wrapperMock.libspdm_init_connection_w(any(), eq(true)))
                .thenReturn(LIBSPDM_STATUS_SUCCESS);
            doAnswer(invocation -> {
                final Object[] arguments = invocation.getArguments();
                final ByteBuffer buffer = (ByteBuffer) arguments[1];
                buffer.put((byte) expectedSpdmVersion);
                buffer.rewind();
                return null;
            }).when(wrapperMock).libspdm_get_version_w(any(), any());

            // when
            final String result = sut.getVersion();

            // then
            assertEquals(toHex(expectedSpdmVersion), result);
        }
    }

    @Test
    void getDigest_ConnectionNotInitialized_InitializesConnection() {
        // given
        try (var wrapperMockedStatic = mockStatic(LibSpdmLibraryWrapperImpl.class)) {
            mockWrapper();
            prepareLibConfig();
            prepareSpdmContextAndScratchBufferSize();

            when(wrapperMock.libspdm_init_connection_w(any(), eq(false)))
                .thenReturn(LIBSPDM_STATUS_SUCCESS);

            // when
            assertDoesNotThrow(sut::getDigest);

            // then
            assertTrue(sut.isConnectionInitialized());
        }
    }

    @Test
    void getDigest_ConnectionAlreadyInitialized_SkipsInitialization() {
        // given
        try (var wrapperMockedStatic = mockStatic(LibSpdmLibraryWrapperImpl.class)) {
            mockWrapper();
            prepareLibConfig();
            prepareSpdmContextAndScratchBufferSize();

            final SpdmProtocol12Impl spdmProtocol12Spy = mockConnectionAlreadyInitialized();

            // when
            assertDoesNotThrow(spdmProtocol12Spy::getDigest);

            // then
            verify(wrapperMock, never()).libspdm_init_connection_w(any(), anyBoolean());
        }
    }

    @Test
    void getDigest_Success() throws Exception {
        // given
        try (var wrapperMockedStatic = mockStatic(LibSpdmLibraryWrapperImpl.class)) {
            mockWrapper();
            prepareLibConfig();
            prepareSpdmContextAndScratchBufferSize();

            final SpdmProtocol12Impl sutSpy = mockConnectionAlreadyInitialized();

            when(wrapperMock.libspdm_get_digest_w(any(), any(), any()))
                .thenAnswer((Answer<Long>) invocation -> {
                    final Object[] arguments = invocation.getArguments();
                    final Pointer slotMask = (Pointer) arguments[1];
                    final Pointer digests = (Pointer) arguments[2];
                    slotMask.setByte(0, SLOT_MASK_GOOD);
                    for (int i = 0; i < DIGEST.length; i++) {
                        digests.setByte(i, DIGEST[i]);
                    }

                    return LIBSPDM_STATUS_SUCCESS;
                });


            // when
            final SpdmGetDigestResult result = sutSpy.getDigest();

            // then
            assertArrayEquals(new byte[]{SLOT_MASK_GOOD}, result.slotMask());
            assertArrayEquals(DIGEST, result.digests());
        }
    }

    @Test
    void getCerts_ConnectionNotInitialized_InitializesConnection() {
        // given
        try (var wrapperMockedStatic = mockStatic(LibSpdmLibraryWrapperImpl.class)) {
            mockWrapper();
            prepareLibConfig();
            prepareSpdmContextAndScratchBufferSize();

            when(wrapperMock.libspdm_init_connection_w(any(), eq(false)))
                .thenReturn(LIBSPDM_STATUS_SUCCESS);

            // when
            assertDoesNotThrow(() -> sut.getCerts(SLOT_ID));

            // then
            assertTrue(sut.isConnectionInitialized());
        }
    }

    @Test
    void getCerts_ConnectionAlreadyInitialized_SkipsInitialization() {
        // given
        try (var wrapperMockedStatic = mockStatic(LibSpdmLibraryWrapperImpl.class)) {
            mockWrapper();
            prepareLibConfig();
            prepareSpdmContextAndScratchBufferSize();

            final SpdmProtocol12Impl sutSpy = mockConnectionAlreadyInitialized();

            // when
            assertDoesNotThrow(() -> sutSpy.getCerts(SLOT_ID));

            // then
            verify(wrapperMock, never()).libspdm_init_connection_w(any(), anyBoolean());
        }
    }

    @Test
    void getCerts_Success() throws Exception {
        // given
        try (var wrapperMockedStatic = mockStatic(LibSpdmLibraryWrapperImpl.class)) {
            mockWrapper();
            prepareLibConfig();
            prepareSpdmContextAndScratchBufferSize();

            final SpdmProtocol12Impl sutSpy = mockConnectionAlreadyInitialized();

            final byte[] expectedCertChain = new byte[]{1, 2, 3, 4};
            when(wrapperMock.libspdm_get_certificate_w(any(), any(), any(), any()))
                .thenAnswer((Answer<Long>) invocation -> {
                    final Object[] arguments = invocation.getArguments();
                    final Pointer certChainSize = (Pointer) arguments[2];
                    final Pointer certChain = (Pointer) arguments[3];
                    setBufferData(expectedCertChain, certChain, certChainSize);

                    return LIBSPDM_STATUS_SUCCESS;
                });

            // when
            final String result = sutSpy.getCerts(SLOT_ID);

            // then
            assertEquals(toHex(expectedCertChain), result);
        }
    }

    @Test
    void getMeasurements_ConnectionNotInitialized_InitializesConnection() {
        // given
        try (var wrapperMockedStatic = mockStatic(LibSpdmLibraryWrapperImpl.class)) {
            mockWrapper();
            prepareLibConfig();
            prepareSpdmContextAndScratchBufferSize();

            when(wrapperMock.libspdm_init_connection_w(any(), eq(false)))
                .thenReturn(LIBSPDM_STATUS_SUCCESS);

            // when
            assertDoesNotThrow(() -> sut.getMeasurements(SLOT_ID));

            // then
            assertTrue(sut.isConnectionInitialized());
        }
    }

    @Test
    void getMeasurements_ConnectionAlreadyInitialized_SkipsInitialization() {
        // given
        try (var wrapperMockedStatic = mockStatic(LibSpdmLibraryWrapperImpl.class)) {
            mockWrapper();
            prepareLibConfig();
            prepareSpdmContextAndScratchBufferSize();

            final SpdmProtocol12Impl sutSpy = mockConnectionAlreadyInitialized();

            // when
            assertDoesNotThrow(() -> sutSpy.getMeasurements(SLOT_ID));

            // then
            verify(wrapperMock, never()).libspdm_init_connection_w(any(), anyBoolean());
        }
    }

    @Test
    void getMeasurements_Success() throws Exception {
        // given
        try (var wrapperMockedStatic = mockStatic(LibSpdmLibraryWrapperImpl.class)) {
            mockWrapper();
            prepareLibConfig();
            prepareSpdmContextAndScratchBufferSize();

            final SpdmProtocol12Impl sutSpy = mockConnectionAlreadyInitialized();

            final byte[] expectedMeasurements = new byte[]{1, 2, 3, 4};
            when(wrapperMock.libspdm_get_measurement_w(any(), any(), any(), any(), any(), any()))
                .thenAnswer((Answer<Long>) invocation -> {
                    final Object[] arguments = invocation.getArguments();
                    final Pointer measurementRecordLength = (Pointer) arguments[1];
                    final Pointer measurementRecord = (Pointer) arguments[2];
                    setBufferData(expectedMeasurements, measurementRecord, measurementRecordLength);

                    return LIBSPDM_STATUS_SUCCESS;
                });

            // when
            final String result = sutSpy.getMeasurements(SLOT_ID);

            // then
            assertEquals(toHex(expectedMeasurements), result);
        }
    }

    @Test
    void getMeasurements_WithoutSignature_CallsMethodWithOnlyRawBitStreamRequest() throws Exception {
        // given
        try (var wrapperMockedStatic = mockStatic(LibSpdmLibraryWrapperImpl.class)) {
            mockWrapper();
            prepareLibConfig();
            prepareSpdmContextAndScratchBufferSize();

            final SpdmProtocol12Impl sutSpy = mockConnectionAlreadyInitialized();

            when(libSpdmParamsMock.isMeasurementsRequestSignature()).thenReturn(false);

            // when
            sutSpy.getMeasurements(SLOT_ID);

            // then
            verify(wrapperMock).libspdm_get_measurement_w(any(), any(), any(), any(),
                eq(new Uint8(SPDM_GET_MEASUREMENTS_REQUEST_ATTRIBUTES_RAW_BIT_STREAM_REQUESTED)), any());
        }
    }

    @Test
    void getMeasurements_WithSignature_CallsMethodWithSignatureRequest() throws Exception {
        // given
        try (var wrapperMockedStatic = mockStatic(LibSpdmLibraryWrapperImpl.class)) {
            mockWrapper();
            prepareLibConfig();
            prepareSpdmContextAndScratchBufferSize();

            final SpdmProtocol12Impl sutSpy = mockConnectionAlreadyInitialized();

            when(libSpdmParamsMock.isMeasurementsRequestSignature()).thenReturn(true);

            // when
            sutSpy.getMeasurements(SLOT_ID);

            // then
            verify(wrapperMock).libspdm_get_measurement_w(any(), any(), any(), any(),
                eq(new Uint8(SPDM_GET_MEASUREMENTS_REQUEST_ATTRIBUTES_GENERATE_SIGNATURE |
                    SPDM_GET_MEASUREMENTS_REQUEST_ATTRIBUTES_RAW_BIT_STREAM_REQUESTED)), any());
        }
    }

    private void verifyCallbacksAreRegistered() {
        verify(wrapperMock)
            .set_callbacks(any(SessionCallbacks.class));
    }

    private void mockWrapper() {
        when(LibSpdmLibraryWrapperImpl.getInstance()).thenReturn(wrapperMock);
    }

    private void prepareLibConfig() {
        doReturn(libConfigMock).when(appContextMock).getLibConfig();
        doReturn(libSpdmParamsMock).when(libConfigMock).getLibSpdmParams();
        doReturn(SPDM_CT_EXP).when(libSpdmParamsMock).getCtExponent();
    }

    private void prepareSpdmContextSize() {
        final NativeSize spdmContextSize = new NativeSize(100);
        when(wrapperMock.libspdm_get_context_size_w()).thenReturn(spdmContextSize);
    }

    private void prepareSpdmContextAndScratchBufferSize() {
        prepareSpdmContextSize();

        final NativeSize scratchBufferSize = new NativeSize(500);
        when(wrapperMock.libspdm_get_sizeof_required_scratch_buffer_w(any())).thenReturn(scratchBufferSize);
    }

    private static SpdmProtocol12Impl mockConnectionAlreadyInitialized() {
        final SpdmProtocol12Impl sut = new SpdmProtocol12Impl();
        final SpdmProtocol12Impl spdmProtocol12Spy = Mockito.spy(sut);
        when(spdmProtocol12Spy.isConnectionInitialized()).thenReturn(true);
        return spdmProtocol12Spy;
    }

    private static void setBufferData(byte[] dataToSet, Pointer buffer, Pointer bufferSize) {
        buffer.setByte(0, dataToSet[0]);
        buffer.setByte(1, dataToSet[1]);
        buffer.setByte(2, dataToSet[2]);
        buffer.setByte(3, dataToSet[3]);

        bufferSize.setInt(0, dataToSet.length);
    }
}

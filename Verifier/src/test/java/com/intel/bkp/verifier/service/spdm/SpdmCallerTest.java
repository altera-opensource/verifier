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

package com.intel.bkp.verifier.service.spdm;

import com.intel.bkp.crypto.constants.CryptoConstants;
import com.intel.bkp.verifier.exceptions.VerifierRuntimeException;
import com.intel.bkp.verifier.jna.LibSpdmLibraryWrapperImpl;
import com.intel.bkp.verifier.jna.LibSpdmLibraryWrapperImpl.LibSpdmLibraryWrapper;
import com.intel.bkp.verifier.jna.model.MctpDecodeCallback;
import com.intel.bkp.verifier.jna.model.MctpEncodeCallback;
import com.intel.bkp.verifier.jna.model.MctpGetHeaderSizeCallback;
import com.intel.bkp.verifier.jna.model.NativeSize;
import com.intel.bkp.verifier.jna.model.PrintCallback;
import com.intel.bkp.verifier.jna.model.SpdmDeviceAcquireReceiverBufferCallback;
import com.intel.bkp.verifier.jna.model.SpdmDeviceAcquireSenderBufferCallback;
import com.intel.bkp.verifier.jna.model.SpdmDeviceReceiveMessageCallback;
import com.intel.bkp.verifier.jna.model.SpdmDeviceReleaseReceiverBufferCallback;
import com.intel.bkp.verifier.jna.model.SpdmDeviceReleaseSenderBufferCallback;
import com.intel.bkp.verifier.jna.model.SpdmDeviceSendMessageCallback;
import com.intel.bkp.verifier.jna.model.Uint8;
import com.intel.bkp.verifier.model.LibConfig;
import com.intel.bkp.verifier.model.LibSpdmParams;
import com.intel.bkp.verifier.service.certificate.AppContext;
import com.sun.jna.Pointer;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.MockedStatic;
import org.mockito.Mockito;
import org.mockito.junit.jupiter.MockitoExtension;
import org.mockito.stubbing.Answer;

import java.lang.reflect.Field;
import java.nio.ByteBuffer;

import static com.intel.bkp.utils.HexConverter.toHex;
import static com.intel.bkp.verifier.jna.model.SpdmConstants.LIBSPDM_STATUS_SUCCESS;
import static com.intel.bkp.verifier.jna.model.SpdmConstants.SPDM_GET_MEASUREMENTS_REQUEST_ATTRIBUTES_GENERATE_SIGNATURE;
import static com.intel.bkp.verifier.jna.model.SpdmConstants.SPDM_GET_MEASUREMENTS_REQUEST_ATTRIBUTES_RAW_BIT_STREAM_REQUESTED;
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
class SpdmCallerTest {

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
    }

    @AfterEach
    void teardown() {
        resetSingleton(SpdmCaller.class, "INSTANCE");
    }


    static void resetSingleton(Class clazz, String fieldName) {
        Field instance;
        try {
            instance = clazz.getDeclaredField(fieldName);
            instance.setAccessible(true);
            instance.set(null, null);
        } catch (Exception e) {
            throw new RuntimeException();
        }
    }

    @Test
    void getInstance_preparesContextAndReturnsCallerInstance() {
        // given
        try (var wrapperMockedStatic = mockStatic(LibSpdmLibraryWrapperImpl.class)) {
            mockWrapper();
            prepareLibConfig();
            prepareSpdmContextAndScratchBufferSize();

            // when
            final SpdmCaller spdmCaller = SpdmCaller.getInstance();

            // then
            final Pointer spdmContext = spdmCaller.getSpdmContext();
            final Pointer scratchBuffer = spdmCaller.getScratchBuffer();

            verify(wrapperMock).libspdm_get_context_size_w();
            verify(wrapperMock).libspdm_prepare_context_w(eq(spdmContext));
            verify(wrapperMock).libspdm_get_sizeof_required_scratch_buffer_w(eq(spdmContext));
            verify(wrapperMock).libspdm_set_scratch_buffer_w(eq(spdmContext), eq(scratchBuffer), any());
            verifyCallbacksAreRegistered();
        }
    }

    @Test
    void getInstance_prepareContextFails_Throws() {
        // given
        try (var wrapperMockedStatic = mockStatic(LibSpdmLibraryWrapperImpl.class)) {
            mockWrapper();
            prepareSpdmContextSize();

            when(wrapperMock.libspdm_prepare_context_w(any())).thenReturn(1L);

            // when-then
            final VerifierRuntimeException ex = assertThrows(VerifierRuntimeException.class, SpdmCaller::getInstance);
            assertEquals("Failed to initialize SPDM context.", ex.getMessage());
        }
    }


    @Test
    void getInstance_WrapperLibraryNotLoaded_Throws() {
        // given
        try (var wrapperMockedStatic = mockStatic(LibSpdmLibraryWrapperImpl.class)) {
            when(LibSpdmLibraryWrapperImpl.getInstance()).thenThrow(new UnsatisfiedLinkError());

            // when-then
            final VerifierRuntimeException ex = assertThrows(VerifierRuntimeException.class, SpdmCaller::getInstance);
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
            final SpdmCaller spdmCaller = SpdmCaller.getInstance();
            final Pointer spdmContext = spdmCaller.getSpdmContext();

            when(wrapperMock.libspdm_init_connection_w(spdmContext, true))
                .thenReturn(LIBSPDM_STATUS_SUCCESS);
            doAnswer(invocation -> {
                final Object[] arguments = invocation.getArguments();
                final ByteBuffer buffer = (ByteBuffer) arguments[1];
                buffer.put((byte) expectedSpdmVersion);
                buffer.rewind();
                return null;
            }).when(wrapperMock).libspdm_get_version_w(eq(spdmContext), any());

            // when
            final String result = spdmCaller.getVersion();

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

            final SpdmCaller spdmCaller = SpdmCaller.getInstance();
            final Pointer spdmContext = spdmCaller.getSpdmContext();

            when(wrapperMock.libspdm_init_connection_w(spdmContext, false))
                .thenReturn(LIBSPDM_STATUS_SUCCESS);

            // when
            assertDoesNotThrow(spdmCaller::getDigest);

            // then
            assertTrue(spdmCaller.isConnectionInitialized());
        }
    }

    @Test
    void getDigest_ConnectionAlreadyInitialized_SkipsInitialization() {
        // given
        try (var wrapperMockedStatic = mockStatic(LibSpdmLibraryWrapperImpl.class)) {
            mockWrapper();
            prepareLibConfig();
            prepareSpdmContextAndScratchBufferSize();

            final SpdmCaller spdmCallerSpy = mockConnectionAlreadyInitialized();

            // when
            assertDoesNotThrow(spdmCallerSpy::getDigest);

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

            final SpdmCaller spdmCallerSpy = mockConnectionAlreadyInitialized();
            final Pointer spdmContext = spdmCallerSpy.getSpdmContext();

            when(wrapperMock.libspdm_get_digest_w(eq(spdmContext), any(), any()))
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
            final SpdmGetDigestResult result = spdmCallerSpy.getDigest();

            // then
            assertArrayEquals(new byte[] {SLOT_MASK_GOOD}, result.slotMask());
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

            final SpdmCaller spdmCaller = SpdmCaller.getInstance();
            final Pointer spdmContext = spdmCaller.getSpdmContext();

            when(wrapperMock.libspdm_init_connection_w(spdmContext, false))
                .thenReturn(LIBSPDM_STATUS_SUCCESS);

            // when
            assertDoesNotThrow(() -> spdmCaller.getCerts(SLOT_ID));

            // then
            assertTrue(spdmCaller.isConnectionInitialized());
        }
    }

    @Test
    void getCerts_ConnectionAlreadyInitialized_SkipsInitialization() {
        // given
        try (var wrapperMockedStatic = mockStatic(LibSpdmLibraryWrapperImpl.class)) {
            mockWrapper();
            prepareLibConfig();
            prepareSpdmContextAndScratchBufferSize();

            final SpdmCaller spdmCallerSpy = mockConnectionAlreadyInitialized();

            // when
            assertDoesNotThrow(() -> spdmCallerSpy.getCerts(SLOT_ID));

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

            final SpdmCaller spdmCallerSpy = mockConnectionAlreadyInitialized();
            final Pointer spdmContext = spdmCallerSpy.getSpdmContext();

            final byte[] expectedCertChain = new byte[]{1, 2, 3, 4};
            when(wrapperMock.libspdm_get_certificate_w(eq(spdmContext), any(), any(), any()))
                .thenAnswer((Answer<Long>) invocation -> {
                    final Object[] arguments = invocation.getArguments();
                    final Pointer certChainSize = (Pointer) arguments[2];
                    final Pointer certChain = (Pointer) arguments[3];
                    setBufferData(expectedCertChain, certChain, certChainSize);

                    return LIBSPDM_STATUS_SUCCESS;
                });

            // when
            final String result = spdmCallerSpy.getCerts(SLOT_ID);

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

            final SpdmCaller spdmCaller = SpdmCaller.getInstance();
            final Pointer spdmContext = spdmCaller.getSpdmContext();

            when(wrapperMock.libspdm_init_connection_w(spdmContext, false))
                .thenReturn(LIBSPDM_STATUS_SUCCESS);

            // when
            assertDoesNotThrow(() -> spdmCaller.getMeasurements(SLOT_ID));

            // then
            assertTrue(spdmCaller.isConnectionInitialized());
        }
    }

    @Test
    void getMeasurements_ConnectionAlreadyInitialized_SkipsInitialization() {
        // given
        try (var wrapperMockedStatic = mockStatic(LibSpdmLibraryWrapperImpl.class)) {
            mockWrapper();
            prepareLibConfig();
            prepareSpdmContextAndScratchBufferSize();

            final SpdmCaller spdmCallerSpy = mockConnectionAlreadyInitialized();

            // when
            assertDoesNotThrow(() -> spdmCallerSpy.getMeasurements(SLOT_ID));

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

            final SpdmCaller spdmCallerSpy = mockConnectionAlreadyInitialized();
            final Pointer spdmContext = spdmCallerSpy.getSpdmContext();

            final byte[] expectedMeasurements = new byte[]{1, 2, 3, 4};
            when(wrapperMock.libspdm_get_measurement_w(eq(spdmContext), any(), any(), any(), any(), any()))
                .thenAnswer((Answer<Long>) invocation -> {
                    final Object[] arguments = invocation.getArguments();
                    final Pointer measurementRecordLength = (Pointer) arguments[1];
                    final Pointer measurementRecord = (Pointer) arguments[2];
                    setBufferData(expectedMeasurements, measurementRecord, measurementRecordLength);

                    return LIBSPDM_STATUS_SUCCESS;
                });

            // when
            final String result = spdmCallerSpy.getMeasurements(SLOT_ID);

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

            final SpdmCaller spdmCallerSpy = mockConnectionAlreadyInitialized();
            final Pointer spdmContext = spdmCallerSpy.getSpdmContext();

            when(libSpdmParamsMock.isMeasurementsRequestSignature()).thenReturn(false);

            // when
            spdmCallerSpy.getMeasurements(SLOT_ID);

            // then
            verify(wrapperMock).libspdm_get_measurement_w(eq(spdmContext), any(), any(), any(),
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

            final SpdmCaller spdmCallerSpy = mockConnectionAlreadyInitialized();
            final Pointer spdmContext = spdmCallerSpy.getSpdmContext();

            when(libSpdmParamsMock.isMeasurementsRequestSignature()).thenReturn(true);

            // when
            spdmCallerSpy.getMeasurements(SLOT_ID);

            // then
            verify(wrapperMock).libspdm_get_measurement_w(eq(spdmContext), any(), any(), any(),
                eq(new Uint8(SPDM_GET_MEASUREMENTS_REQUEST_ATTRIBUTES_GENERATE_SIGNATURE |
                    SPDM_GET_MEASUREMENTS_REQUEST_ATTRIBUTES_RAW_BIT_STREAM_REQUESTED)), any());
        }
    }

    private void verifyCallbacksAreRegistered() {
        verify(wrapperMock)
            .register_printf_callback(any(PrintCallback.class));
        verify(wrapperMock)
            .register_mctp_encode_callback(any(MctpEncodeCallback.class));
        verify(wrapperMock)
            .register_mctp_decode_callback(any(MctpDecodeCallback.class));
        verify(wrapperMock)
            .register_spdm_device_send_message_callback(any(SpdmDeviceSendMessageCallback.class));
        verify(wrapperMock)
            .register_spdm_device_receive_message_callback(any(SpdmDeviceReceiveMessageCallback.class));
        verify(wrapperMock)
            .register_libspdm_transport_mctp_get_header_size_cust_callback(any(MctpGetHeaderSizeCallback.class));
        verify(wrapperMock)
            .register_spdm_device_acquire_sender_buffer(any(SpdmDeviceAcquireSenderBufferCallback.class));
        verify(wrapperMock)
            .register_spdm_device_release_sender_buffer(any(SpdmDeviceReleaseSenderBufferCallback.class));
        verify(wrapperMock)
            .register_spdm_device_acquire_receiver_buffer(any(SpdmDeviceAcquireReceiverBufferCallback.class));
        verify(wrapperMock)
            .register_spdm_device_release_receiver_buffer(any(SpdmDeviceReleaseReceiverBufferCallback.class));
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

    private static SpdmCaller mockConnectionAlreadyInitialized() {
        final SpdmCaller spdmCaller = SpdmCaller.getInstance();
        final SpdmCaller spdmCallerSpy = Mockito.spy(spdmCaller);
        when(spdmCallerSpy.isConnectionInitialized()).thenReturn(true);
        return spdmCallerSpy;
    }

    private static void setBufferData(byte[] dataToSet, Pointer buffer, Pointer bufferSize) {
        buffer.setByte(0, dataToSet[0]);
        buffer.setByte(1, dataToSet[1]);
        buffer.setByte(2, dataToSet[2]);
        buffer.setByte(3, dataToSet[3]);

        bufferSize.setInt(0, dataToSet.length);
    }
}

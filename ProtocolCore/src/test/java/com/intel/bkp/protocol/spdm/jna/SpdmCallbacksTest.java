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

package com.intel.bkp.protocol.spdm.jna;

import com.intel.bkp.protocol.spdm.exceptions.BufferOperationFailed;
import com.intel.bkp.protocol.spdm.jna.model.LibSpdmReturn;
import com.intel.bkp.protocol.spdm.jna.model.MessageLogger;
import com.intel.bkp.protocol.spdm.jna.model.MessageSender;
import com.intel.bkp.protocol.spdm.jna.model.NativeSize;
import com.intel.bkp.protocol.spdm.jna.model.Uint64;
import com.sun.jna.Pointer;
import com.sun.jna.ptr.PointerByReference;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.MockedStatic;
import org.mockito.Mockito;
import org.mockito.junit.jupiter.MockitoExtension;

import java.nio.ByteBuffer;
import java.util.Optional;

import static com.intel.bkp.protocol.spdm.jna.model.SpdmConstants.LIBSPDM_STATUS_SPDM_INTERNAL_EXCEPTION;
import static com.intel.bkp.protocol.spdm.jna.model.SpdmConstants.LIBSPDM_STATUS_SPDM_NOT_SUPPORTED;
import static com.intel.bkp.protocol.spdm.jna.model.SpdmConstants.LIBSPDM_STATUS_SUCCESS;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.mockStatic;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class SpdmCallbacksTest {

    private static final LibSpdmReturn RETURN_SUCCESS = new LibSpdmReturn(LIBSPDM_STATUS_SUCCESS);
    private static final LibSpdmReturn RETURN_EXCEPTION = new LibSpdmReturn(LIBSPDM_STATUS_SPDM_INTERNAL_EXCEPTION);
    private static final LibSpdmReturn RETURN_NOT_SUPPORTED = new LibSpdmReturn(LIBSPDM_STATUS_SPDM_NOT_SUPPORTED);
    private static final long EXPECTED_MESSAGE_SIZE_LONG = 100L;
    public static final RuntimeException RUNTIME_EXCEPTION = new RuntimeException("TEST");

    private static MockedStatic<SpdmUtils> spdmUtilsMockedStatic;

    @BeforeAll
    public static void prepareStaticMock() {
        spdmUtilsMockedStatic = mockStatic(SpdmUtils.class);
    }

    @AfterAll
    public static void closeStaticMock() {
        spdmUtilsMockedStatic.close();
    }

    private final NativeSize srcMessageSize = new NativeSize(EXPECTED_MESSAGE_SIZE_LONG);
    private final ByteBuffer srcMessageBuffer = ByteBuffer.allocate((int) EXPECTED_MESSAGE_SIZE_LONG);
    private final NativeSize requestSize = new NativeSize(EXPECTED_MESSAGE_SIZE_LONG);
    private final ByteBuffer requestBuffer = ByteBuffer.allocate((int) EXPECTED_MESSAGE_SIZE_LONG);
    private final Uint64 timeout = new Uint64(100);

    @Mock
    private Pointer spdmContext;
    @Mock
    private Pointer sessionId;
    @Mock
    private PointerByReference sessionIdP;
    @Mock
    private Pointer srcMessage;
    @Mock
    private PointerByReference dstMessageP;
    @Mock
    private Pointer dstMessageSize;
    @Mock
    private Pointer isAppMessage;
    @Mock
    private PointerByReference msgBuf;

    @Mock
    private Pointer request;
    @Mock
    private PointerByReference response;
    @Mock
    private Pointer responseSize;

    @Mock
    private NativeMemoryHandler nativeMemoryHandlerMock;

    @Mock
    private MessageSender messageSender;

    @Mock
    private MessageLogger messageLogger;

    @InjectMocks
    private SpdmCallbacks sut;

    @Test
    void mctpEncode_Success() {
        // given
        when(srcMessage.getByteBuffer(0, EXPECTED_MESSAGE_SIZE_LONG)).thenReturn(srcMessageBuffer);

        // when
        final LibSpdmReturn result = sut.mctpEncode(spdmContext, sessionId, true, true,
            srcMessageSize, srcMessage, dstMessageSize, dstMessageP);

        // then
        assertEquals(RETURN_SUCCESS, result);
        spdmUtilsMockedStatic.verify(
            () -> SpdmUtils.copyBuffer(any(), eq(dstMessageP), eq(dstMessageSize)));
    }

    @Test
    void mctpEncode_ErrorOccurredDuringParsing_Throws() {
        // given
        when(srcMessage.getByteBuffer(0, EXPECTED_MESSAGE_SIZE_LONG)).thenThrow(RUNTIME_EXCEPTION);

        // when
        final LibSpdmReturn result = sut.mctpEncode(spdmContext, sessionId, true, true,
            srcMessageSize, srcMessage, dstMessageSize, dstMessageP);

        // then
        assertEquals(RETURN_EXCEPTION, result);
    }

    @Test
    void mctpDecode_Success() {
        // given
        when(srcMessage.getByteBuffer(0, EXPECTED_MESSAGE_SIZE_LONG)).thenReturn(srcMessageBuffer);

        // when
        final LibSpdmReturn result = sut.mctpDecode(spdmContext, sessionIdP, isAppMessage, true,
            srcMessageSize, srcMessage, dstMessageSize, dstMessageP);

        // then
        assertEquals(RETURN_SUCCESS, result);
        spdmUtilsMockedStatic.verify(
            () -> SpdmUtils.copyBuffer(any(), eq(dstMessageP), eq(dstMessageSize)));
    }

    @Test
    void mctpDecode_ErrorOccurredDuringParsing_Throws() {
        // given
        when(srcMessage.getByteBuffer(0, EXPECTED_MESSAGE_SIZE_LONG)).thenThrow(RUNTIME_EXCEPTION);

        // when
        final LibSpdmReturn result = sut.mctpDecode(spdmContext, sessionIdP, isAppMessage, true,
            srcMessageSize, srcMessage, dstMessageSize, dstMessageP);

        // then
        assertEquals(RETURN_EXCEPTION, result);
    }

    @Test
    void spdmDeviceReleaseSenderBuffer_Success() throws BufferOperationFailed {
        // given
        final Pointer msgBuf = Mockito.mock(Pointer.class);

        // when
        sut.spdmDeviceReleaseSenderBuffer(spdmContext, msgBuf);

        // then
        verify(nativeMemoryHandlerMock).releaseSenderBuffer();
    }

    @Test
    void spdmDeviceReleaseReceiverBuffer_Success() throws BufferOperationFailed {
        // given
        final Pointer msgBuf = Mockito.mock(Pointer.class);

        // when
        sut.spdmDeviceReleaseReceiverBuffer(spdmContext, msgBuf);

        // then
        verify(nativeMemoryHandlerMock).releaseReceiverBuffer();
    }

    @Test
    void spdmDeviceAcquireSenderBuffer_Success() throws BufferOperationFailed {
        // when
        final LibSpdmReturn result = sut.spdmDeviceAcquireSenderBuffer(spdmContext, msgBuf);

        // then
        assertEquals(RETURN_SUCCESS, result);
        verify(nativeMemoryHandlerMock).acquireSenderBuffer(eq(msgBuf));
    }

    @Test
    void spdmDeviceAcquireSenderBuffer_AcquireThrows_ReturnsException() throws BufferOperationFailed {
        // given
        doThrow(RUNTIME_EXCEPTION).when(nativeMemoryHandlerMock).acquireSenderBuffer(msgBuf);

        // when
        final LibSpdmReturn result = sut.spdmDeviceAcquireSenderBuffer(spdmContext, msgBuf);

        // then
        assertEquals(RETURN_EXCEPTION, result);
    }

    @Test
    void spdmDeviceAcquireReceiverBuffer_Success() throws BufferOperationFailed {
        // when
        final LibSpdmReturn result = sut.spdmDeviceAcquireReceiverBuffer(spdmContext, msgBuf);

        // then
        assertEquals(RETURN_SUCCESS, result);
        verify(nativeMemoryHandlerMock).acquireReceiverBuffer(eq(msgBuf));
    }

    @Test
    void spdmDeviceAcquireReceiverBuffer_AcquireThrows_ReturnsException() throws BufferOperationFailed {
        // given
        doThrow(RUNTIME_EXCEPTION).when(nativeMemoryHandlerMock).acquireReceiverBuffer(msgBuf);

        // when
        final LibSpdmReturn result = sut.spdmDeviceAcquireReceiverBuffer(spdmContext, msgBuf);

        // then
        assertEquals(RETURN_EXCEPTION, result);
    }

    @Test
    void spdmDeviceSendMessage_Success() {
        // given
        when(request.getByteBuffer(0, EXPECTED_MESSAGE_SIZE_LONG)).thenReturn(requestBuffer);

        // when
        final LibSpdmReturn result = sut.spdmDeviceSendMessage(spdmContext, requestSize, request, timeout);

        // then
        assertEquals(RETURN_SUCCESS, result);
    }

    @Test
    void spdmDeviceSendMessage_SendingFailed_ReturnsException() throws Exception {
        // given
        when(request.getByteBuffer(0, EXPECTED_MESSAGE_SIZE_LONG)).thenReturn(requestBuffer);

        doThrow(RUNTIME_EXCEPTION).when(messageSender).sendMessage(any(), eq(requestBuffer));

        // when
        final LibSpdmReturn result = sut.spdmDeviceSendMessage(spdmContext, requestSize, request, timeout);

        // then
        assertEquals(RETURN_EXCEPTION, result);
    }

    @Test
    void spdmDeviceReceiveMessage_Success() throws Exception {
        // given
        when(messageSender.receiveResponse()).thenReturn(Optional.of(new byte[]{1, 2, 3, 4}));

        // when
        final LibSpdmReturn result =
            sut.spdmDeviceReceiveMessage(spdmContext, responseSize, response, timeout);

        // then
        assertEquals(RETURN_SUCCESS, result);
        spdmUtilsMockedStatic.verify(
            () -> SpdmUtils.copyBuffer(any(), eq(response), eq(responseSize)));
    }

    @Test
    void spdmDeviceReceiveMessage_EmptyResponse_ReturnsNotSupported() throws Exception {
        // given
        when(messageSender.receiveResponse()).thenReturn(Optional.empty());

        // when
        final LibSpdmReturn result =
            sut.spdmDeviceReceiveMessage(spdmContext, responseSize, response, timeout);

        // then
        assertEquals(RETURN_NOT_SUPPORTED, result);
    }

    @Test
    void spdmDeviceReceiveMessage_ExceptionOccurred_ReturnsException() throws Exception {
        // given
        doThrow(RUNTIME_EXCEPTION).when(messageSender).receiveResponse();

        // when
        final LibSpdmReturn result =
            sut.spdmDeviceReceiveMessage(spdmContext, responseSize, response, timeout);

        // then
        assertEquals(RETURN_EXCEPTION, result);
        spdmUtilsMockedStatic.verify(
            () -> SpdmUtils.copyBuffer(any(), eq(response), eq(responseSize)), never());
    }
}

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

import com.intel.bkp.verifier.command.messages.mctp.MctpMessageBuilder;
import com.intel.bkp.verifier.exceptions.UnknownCommandException;
import com.intel.bkp.verifier.jna.model.LibSpdmReturn;
import com.intel.bkp.verifier.jna.model.NativeSize;
import com.intel.bkp.verifier.jna.model.Uint32;
import com.intel.bkp.verifier.jna.model.Uint64;
import com.intel.bkp.verifier.model.CommandIdentifier;
import com.sun.jna.Pointer;
import com.sun.jna.ptr.PointerByReference;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.MockedStatic;
import org.mockito.Mockito;
import org.mockito.junit.jupiter.MockitoExtension;

import java.nio.ByteBuffer;

import static com.intel.bkp.verifier.jna.model.SpdmConstants.LIBSPDM_STATUS_SPDM_NOT_SUPPORTED;
import static com.intel.bkp.verifier.jna.model.SpdmConstants.LIBSPDM_STATUS_SPDM_VERIFIER_EXCEPTION;
import static com.intel.bkp.verifier.jna.model.SpdmConstants.LIBSPDM_STATUS_SUCCESS;
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
    private static final LibSpdmReturn RETURN_EXCEPTION = new LibSpdmReturn(LIBSPDM_STATUS_SPDM_VERIFIER_EXCEPTION);
    private static final LibSpdmReturn RETURN_NOT_SUPPORTED = new LibSpdmReturn(LIBSPDM_STATUS_SPDM_NOT_SUPPORTED);
    private static final long EXPECTED_MESSAGE_SIZE_LONG = 100L;
    public static final RuntimeException RUNTIME_EXCEPTION = new RuntimeException("TEST");

    private static MockedStatic<SpdmUtils> spdmUtilsMockedStatic;
    private static MockedStatic<NativeMemoryHandler> nativeMemoryHandlerMockedStatic;
    private static NativeMemoryHandler nativeMemoryHandlerMock = Mockito.mock(NativeMemoryHandler.class);

    @BeforeAll
    public static void prepareStaticMock() {
        spdmUtilsMockedStatic = mockStatic(SpdmUtils.class);
        nativeMemoryHandlerMockedStatic = mockStatic(NativeMemoryHandler.class);
        when(NativeMemoryHandler.getInstance()).thenReturn(nativeMemoryHandlerMock);
    }

    @AfterAll
    public static void closeStaticMock() {
        spdmUtilsMockedStatic.close();
        nativeMemoryHandlerMockedStatic.close();
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
    private Pointer maxMsgSize;
    @Mock
    private PointerByReference msgBuf;

    @Mock
    private Pointer request;
    @Mock
    private PointerByReference response;
    @Mock
    private Pointer responseSize;

    @Test
    void mctpEncode_Success() {
        // given
        when(srcMessage.getByteBuffer(0, EXPECTED_MESSAGE_SIZE_LONG)).thenReturn(srcMessageBuffer);

        // when
        final LibSpdmReturn result = SpdmCallbacks.mctpEncode(spdmContext, sessionId, true, true,
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
        final LibSpdmReturn result = SpdmCallbacks.mctpEncode(spdmContext, sessionId, true, true,
            srcMessageSize, srcMessage, dstMessageSize, dstMessageP);

        // then
        assertEquals(RETURN_EXCEPTION, result);
    }

    @Test
    void mctpDecode_Success() {
        // given
        when(srcMessage.getByteBuffer(0, EXPECTED_MESSAGE_SIZE_LONG)).thenReturn(srcMessageBuffer);

        // when
        final LibSpdmReturn result = SpdmCallbacks.mctpDecode(spdmContext, sessionIdP, isAppMessage, true,
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
        final LibSpdmReturn result = SpdmCallbacks.mctpDecode(spdmContext, sessionIdP, isAppMessage, true,
            srcMessageSize, srcMessage, dstMessageSize, dstMessageP);

        // then
        assertEquals(RETURN_EXCEPTION, result);
    }

    @Test
    void mctpGetHeaderSize_Success() {
        // when
        final Uint32 result = SpdmCallbacks.mctpGetHeaderSize(spdmContext);

        // then
        assertEquals(MctpMessageBuilder.MCTP_HEADER_SIZE, result.byteValue());
    }

    @Test
    void spdmDeviceReleaseSenderBuffer_Success() {
        // given
        final Pointer msgBuf = Mockito.mock(Pointer.class);

        // when
        SpdmCallbacks.spdmDeviceReleaseSenderBuffer(spdmContext, msgBuf);

        // then
        verify(nativeMemoryHandlerMock).releaseSenderBuffer();
    }

    @Test
    void spdmDeviceReleaseReceiverBuffer_Success() {
        // given
        final Pointer msgBuf = Mockito.mock(Pointer.class);

        // when
        SpdmCallbacks.spdmDeviceReleaseReceiverBuffer(spdmContext, msgBuf);

        // then
        verify(nativeMemoryHandlerMock).releaseReceiverBuffer();
    }

    @Test
    void spdmDeviceAcquireSenderBuffer_Success() {
        // when
        final LibSpdmReturn result = SpdmCallbacks.spdmDeviceAcquireSenderBuffer(spdmContext, maxMsgSize, msgBuf);

        // then
        assertEquals(RETURN_SUCCESS, result);
        verify(nativeMemoryHandlerMock).acquireSenderBuffer(eq(maxMsgSize), eq(msgBuf));
    }

    @Test
    void spdmDeviceAcquireSenderBuffer_AcquireThrows_ReturnsException() {
        // given
        doThrow(RUNTIME_EXCEPTION).when(nativeMemoryHandlerMock).acquireSenderBuffer(maxMsgSize, msgBuf);

        // when
        final LibSpdmReturn result = SpdmCallbacks.spdmDeviceAcquireSenderBuffer(spdmContext, maxMsgSize, msgBuf);

        // then
        assertEquals(RETURN_EXCEPTION, result);
    }

    @Test
    void spdmDeviceAcquireReceiverBuffer_Success() {
        // when
        final LibSpdmReturn result = SpdmCallbacks.spdmDeviceAcquireReceiverBuffer(spdmContext, maxMsgSize, msgBuf);

        // then
        assertEquals(RETURN_SUCCESS, result);
        verify(nativeMemoryHandlerMock).acquireReceiverBuffer(eq(maxMsgSize), eq(msgBuf));
    }

    @Test
    void spdmDeviceAcquireReceiverBuffer_AcquireThrows_ReturnsException() {
        // given
        doThrow(RUNTIME_EXCEPTION).when(nativeMemoryHandlerMock).acquireReceiverBuffer(maxMsgSize, msgBuf);

        // when
        final LibSpdmReturn result = SpdmCallbacks.spdmDeviceAcquireReceiverBuffer(spdmContext, maxMsgSize, msgBuf);

        // then
        assertEquals(RETURN_EXCEPTION, result);
    }

    @Test
    void spdmDeviceSendMessage_Success() {
        // given
        final byte[] response = new byte[]{9, 10, 11, 12};
        when(request.getByteBuffer(0, EXPECTED_MESSAGE_SIZE_LONG)).thenReturn(requestBuffer);

        try (var spdmMessageSenderMockedStatic = mockStatic(SpdmMessageSender.class)) {
            spdmMessageSenderMockedStatic.when(() -> SpdmMessageSender.send(requestBuffer))
                .thenReturn(response);

            // when
            final LibSpdmReturn result = SpdmCallbacks.spdmDeviceSendMessage(spdmContext, requestSize, request, timeout);

            // then
            assertEquals(RETURN_SUCCESS, result);
            verify(nativeMemoryHandlerMock).setResponse(eq(response));
        }
    }

    @Test
    void spdmDeviceSendMessage_UnknownCommandException_ReturnsSpdmNotSupported() {
        // given
        final byte[] response = new byte[]{9, 10, 11, 12};
        when(request.getByteBuffer(0, EXPECTED_MESSAGE_SIZE_LONG)).thenReturn(requestBuffer);

        try (var spdmMessageSenderMockedStatic = mockStatic(SpdmMessageSender.class)) {
            spdmMessageSenderMockedStatic.when(() -> SpdmMessageSender.send(requestBuffer))
                .thenThrow(new UnknownCommandException(CommandIdentifier.MCTP.name(), 1, 2, 3));

            // when
            final LibSpdmReturn result = SpdmCallbacks.spdmDeviceSendMessage(spdmContext, requestSize, request, timeout);

            // then
            assertEquals(RETURN_NOT_SUPPORTED, result);
            verify(nativeMemoryHandlerMock, never()).setResponse(any());
        }
    }

    @Test
    void spdmDeviceSendMessage_SendingFailed_ReturnsException() {
        // given
        when(request.getByteBuffer(0, EXPECTED_MESSAGE_SIZE_LONG)).thenReturn(requestBuffer);

        try (var spdmMessageSenderMockedStatic = mockStatic(SpdmMessageSender.class)) {
            spdmMessageSenderMockedStatic.when(() -> SpdmMessageSender.send(requestBuffer))
                .thenThrow(RUNTIME_EXCEPTION);

            // when
            final LibSpdmReturn result = SpdmCallbacks.spdmDeviceSendMessage(spdmContext, requestSize, request, timeout);

            // then
            assertEquals(RETURN_EXCEPTION, result);
            verify(nativeMemoryHandlerMock, never()).setResponse(any());
        }
    }

    @Test
    void spdmDeviceReceiveMessage_Success() {
        // given
        when(nativeMemoryHandlerMock.getResponse()).thenReturn(new byte[]{1, 2, 3, 4});

        // when
        final LibSpdmReturn result =
            SpdmCallbacks.spdmDeviceReceiveMessage(spdmContext, responseSize, response, timeout);

        // then
        assertEquals(RETURN_SUCCESS, result);
        spdmUtilsMockedStatic.verify(
            () -> SpdmUtils.copyBuffer(any(), eq(response), eq(responseSize)));
    }

    @Test
    void spdmDeviceReceiveMessage_ExceptionOccurred_ReturnsException() {
        // given
        doThrow(RUNTIME_EXCEPTION).when(nativeMemoryHandlerMock).getResponse();

        // when
        final LibSpdmReturn result =
            SpdmCallbacks.spdmDeviceReceiveMessage(spdmContext, responseSize, response, timeout);

        // then
        assertEquals(RETURN_EXCEPTION, result);
        spdmUtilsMockedStatic.verify(
            () -> SpdmUtils.copyBuffer(any(), eq(response), eq(responseSize)), never());
    }
}

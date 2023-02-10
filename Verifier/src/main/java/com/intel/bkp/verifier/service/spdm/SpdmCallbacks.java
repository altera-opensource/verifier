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

import com.intel.bkp.verifier.command.messages.mctp.MctpMessageBuilder;
import com.intel.bkp.verifier.exceptions.UnknownCommandException;
import com.intel.bkp.verifier.jna.model.LibSpdmReturn;
import com.intel.bkp.verifier.jna.model.NativeSize;
import com.intel.bkp.verifier.jna.model.Uint32;
import com.intel.bkp.verifier.jna.model.Uint64;
import com.sun.jna.Pointer;
import com.sun.jna.ptr.PointerByReference;
import lombok.extern.slf4j.Slf4j;

import java.nio.ByteBuffer;

import static com.intel.bkp.verifier.jna.model.SpdmConstants.LIBSPDM_STATUS_SPDM_NOT_SUPPORTED;
import static com.intel.bkp.verifier.jna.model.SpdmConstants.LIBSPDM_STATUS_SPDM_VERIFIER_EXCEPTION;
import static com.intel.bkp.verifier.jna.model.SpdmConstants.LIBSPDM_STATUS_SUCCESS;
import static com.intel.bkp.verifier.service.spdm.SpdmUtils.copyBuffer;

@Slf4j
public class SpdmCallbacks {

    private static final NativeMemoryHandler NATIVE_MEMORY_HANDLER = NativeMemoryHandler.getInstance();


    static void printfCallback(String message) {
        log.debug("[SPDM Wrapper]: " + message);
    }

    static LibSpdmReturn mctpEncode(Pointer spdmContext, Pointer sessionId, boolean isAppMessage,
                                    boolean isRequester,
                                    NativeSize messageSize, Pointer message, Pointer transportMessageSize,
                                    PointerByReference transportMessage) {
        try {
            final ByteBuffer messageBuffer = message.getByteBuffer(0, messageSize.longValue());
            SpdmMessageResponseHandler.logMessage(messageBuffer);
            final ByteBuffer mctpMessageBuffer = buildMctpMessageBuffer(messageBuffer);

            copyBuffer(mctpMessageBuffer, transportMessage, transportMessageSize);

            return new LibSpdmReturn(LIBSPDM_STATUS_SUCCESS);
        } catch (Exception e) {
            log.error("MCTP Encode failed: {}", e.getMessage());
            log.debug("Stacktrace: ", e);
            return new LibSpdmReturn(LIBSPDM_STATUS_SPDM_VERIFIER_EXCEPTION);
        }
    }

    static LibSpdmReturn mctpDecode(Pointer spdmContext, PointerByReference sessionId, Pointer isAppMessage,
                                    boolean isRequester,
                                    NativeSize transportMessageSize, Pointer transportMessage, Pointer messageSize,
                                    PointerByReference message) {
        try {
            final ByteBuffer transportMessageBuffer =
                transportMessage.getByteBuffer(0, transportMessageSize.longValue());
            final ByteBuffer mctpMessagePayloadBuffer = getMctpMessagePayload(transportMessageBuffer);
            SpdmMessageResponseHandler.logResponse(mctpMessagePayloadBuffer);

            copyBuffer(mctpMessagePayloadBuffer, message, messageSize);

            return new LibSpdmReturn(LIBSPDM_STATUS_SUCCESS);
        } catch (Exception e) {
            log.error("MCTP Decode failed.", e.getMessage());
            log.debug("Stacktrace: ", e);
            return new LibSpdmReturn(LIBSPDM_STATUS_SPDM_VERIFIER_EXCEPTION);
        }
    }

    static Uint32 mctpGetHeaderSize(Pointer spdmContext) {
        return new Uint32(MctpMessageBuilder.MCTP_HEADER_SIZE);
    }

    static LibSpdmReturn spdmDeviceSendMessage(Pointer spdmContext, NativeSize requestSize, Pointer request,
                                               Uint64 timeout) {
        try {
            final ByteBuffer buffer = request.getByteBuffer(0, requestSize.longValue());
            final byte[] response = SpdmMessageSender.send(buffer);
            NATIVE_MEMORY_HANDLER.setResponse(response);

            return new LibSpdmReturn(LIBSPDM_STATUS_SUCCESS);
        } catch (UnknownCommandException e) {
            log.warn("SPDM is not supported on this platform. Error message: {}", e.getMessage());
            return new LibSpdmReturn(LIBSPDM_STATUS_SPDM_NOT_SUPPORTED);
        } catch (Exception e) {
            log.error("Sending message failed.", e.getMessage());
            log.debug("Stacktrace: ", e);
            return new LibSpdmReturn(LIBSPDM_STATUS_SPDM_VERIFIER_EXCEPTION);
        }
    }

    static LibSpdmReturn spdmDeviceReceiveMessage(Pointer spdmContext, Pointer responseSize,
                                                  PointerByReference response,
                                                  Uint64 timeout) {
        try {
            copyBuffer(ByteBuffer.wrap(NATIVE_MEMORY_HANDLER.getResponse()), response, responseSize);
            return new LibSpdmReturn(LIBSPDM_STATUS_SUCCESS);
        } catch (Exception e) {
            log.error("Receiving message failed: {}", e.getMessage());
            log.debug("Stacktrace: ", e);
            return new LibSpdmReturn(LIBSPDM_STATUS_SPDM_VERIFIER_EXCEPTION);
        }
    }

    public static LibSpdmReturn spdmDeviceAcquireSenderBuffer(Pointer spdmContext, Pointer maxMsgSize,
                                                              PointerByReference msgBufPtr) {
        try {
            NATIVE_MEMORY_HANDLER.acquireSenderBuffer(maxMsgSize, msgBufPtr);
            return new LibSpdmReturn(LIBSPDM_STATUS_SUCCESS);
        } catch (Exception e) {
            log.error("Acquire sender buffer failed: {}", e.getMessage());
            log.debug("Stacktrace: ", e);
            return new LibSpdmReturn(LIBSPDM_STATUS_SPDM_VERIFIER_EXCEPTION);
        }
    }

    public static void spdmDeviceReleaseSenderBuffer(Pointer spdmContext, Pointer msgBufPtr) {
        NATIVE_MEMORY_HANDLER.releaseSenderBuffer();
    }

    public static LibSpdmReturn spdmDeviceAcquireReceiverBuffer(Pointer spdmContext, Pointer maxMsgSize,
                                                                PointerByReference msgBufPtr) {
        try {
            NATIVE_MEMORY_HANDLER.acquireReceiverBuffer(maxMsgSize, msgBufPtr);
            return new LibSpdmReturn(LIBSPDM_STATUS_SUCCESS);
        } catch (Exception e) {
            log.error("Acquire receiver buffer failed: {}", e.getMessage());
            log.debug("Stacktrace: ", e);
            return new LibSpdmReturn(LIBSPDM_STATUS_SPDM_VERIFIER_EXCEPTION);
        }
    }

    public static void spdmDeviceReleaseReceiverBuffer(Pointer spdmContext, Pointer msgBufPtr) {
        NATIVE_MEMORY_HANDLER.releaseReceiverBuffer();
    }

    private static ByteBuffer buildMctpMessageBuffer(ByteBuffer messageBuffer) {
        return new MctpMessageBuilder().withPayload(messageBuffer).build().buffer();
    }

    private static ByteBuffer getMctpMessagePayload(ByteBuffer messageBuffer) {
        return new MctpMessageBuilder().parse(messageBuffer).build().getPayloadBuffer();
    }
}

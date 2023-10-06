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

import com.intel.bkp.protocol.spdm.exceptions.SpdmRuntimeException;
import com.intel.bkp.protocol.spdm.jna.model.LibSpdmReturn;
import com.intel.bkp.protocol.spdm.jna.model.MessageLogger;
import com.intel.bkp.protocol.spdm.jna.model.MessageSender;
import com.intel.bkp.protocol.spdm.jna.model.NativeSize;
import com.intel.bkp.protocol.spdm.jna.model.Uint64;
import com.sun.jna.Pointer;
import com.sun.jna.ptr.PointerByReference;
import lombok.Setter;
import lombok.extern.slf4j.Slf4j;

import java.nio.ByteBuffer;
import java.util.Optional;

import static com.intel.bkp.protocol.spdm.jna.SpdmUtils.copyBuffer;
import static com.intel.bkp.protocol.spdm.jna.model.SpdmConstants.LIBSPDM_STATUS_SPDM_INTERNAL_EXCEPTION;
import static com.intel.bkp.protocol.spdm.jna.model.SpdmConstants.LIBSPDM_STATUS_SPDM_NOT_SUPPORTED;
import static com.intel.bkp.protocol.spdm.jna.model.SpdmConstants.LIBSPDM_STATUS_SUCCESS;

@Slf4j
public class SpdmCallbacks {

    private final NativeMemoryHandler nativeMemoryHandler;
    private final MessageSender messageSender;
    private final MessageLogger messageLogger;

    @Setter
    private long spdmContextSize;

    SpdmCallbacks(NativeMemoryHandler nativeMemoryHandler, MessageSender messageSender, MessageLogger messageLogger) {
        this.nativeMemoryHandler = nativeMemoryHandler;
        this.messageSender = messageSender;
        this.messageLogger = messageLogger;
    }

    public SpdmCallbacks(MessageSender messageSender, MessageLogger messageLogger) {
        this.nativeMemoryHandler = new NativeMemoryHandler();
        this.messageSender = messageSender;
        this.messageLogger = messageLogger;
    }

    public void printCallback(String message) {
        log.debug("[SPDM Wrapper] {}", message);
    }

    public LibSpdmReturn mctpEncode(Pointer spdmContext, Pointer sessionId, boolean isAppMessage,
                                    boolean isRequester,
                                    NativeSize messageSize, Pointer message, Pointer transportMessageSize,
                                    PointerByReference transportMessage) {
        try {
            final ByteBuffer messageBuffer = message.getByteBuffer(0, messageSize.longValue());
            messageLogger.logMessage(messageBuffer);
            final ByteBuffer mctpMessageBuffer = messageSender.buildMctpMessageBuffer(messageBuffer);

            copyBuffer(mctpMessageBuffer, transportMessage, transportMessageSize);

            return new LibSpdmReturn(LIBSPDM_STATUS_SUCCESS);
        } catch (Exception e) {
            log.error("MCTP Encode failed: {}", e.getMessage());
            log.debug("Stacktrace: ", e);
            return new LibSpdmReturn(LIBSPDM_STATUS_SPDM_INTERNAL_EXCEPTION);
        }
    }

    public LibSpdmReturn mctpDecode(Pointer spdmContext, PointerByReference sessionId, Pointer isAppMessage,
                                    boolean isRequester,
                                    NativeSize transportMessageSize, Pointer transportMessage, Pointer messageSize,
                                    PointerByReference message) {
        try {
            final ByteBuffer transportMessageBuffer =
                transportMessage.getByteBuffer(0, transportMessageSize.longValue());
            final ByteBuffer mctpMessagePayloadBuffer = messageSender.getMctpMessagePayload(transportMessageBuffer);
            messageLogger.logResponse(mctpMessagePayloadBuffer);

            copyBuffer(mctpMessagePayloadBuffer, message, messageSize);

            return new LibSpdmReturn(LIBSPDM_STATUS_SUCCESS);
        } catch (Exception e) {
            log.error("MCTP Decode failed: {}", e.getMessage());
            log.debug("Stacktrace: ", e);
            return new LibSpdmReturn(LIBSPDM_STATUS_SPDM_INTERNAL_EXCEPTION);
        }
    }

    public LibSpdmReturn spdmDeviceSendMessage(Pointer spdmContext, NativeSize requestSize, Pointer request,
                                               Uint64 timeout) {
        try {
            final ByteBuffer buffer = request.getByteBuffer(0, requestSize.longValue());
            messageSender.sendMessage(spdmContext.getByteBuffer(0, spdmContextSize), buffer);
            return new LibSpdmReturn(LIBSPDM_STATUS_SUCCESS);
        } catch (Exception e) {
            log.error("Sending message failed: {}", e.getMessage());
            log.debug("Stacktrace: ", e);
            return new LibSpdmReturn(LIBSPDM_STATUS_SPDM_INTERNAL_EXCEPTION);
        }
    }

    public LibSpdmReturn spdmDeviceReceiveMessage(Pointer spdmContext, Pointer responseSize,
                                                  PointerByReference response,
                                                  Uint64 timeout) {
        try {
            final Optional<byte[]> possibleResponse = messageSender.receiveResponse();

            if (possibleResponse.isEmpty()) {
                log.error("Response from SPDM Responder is empty.");
                return new LibSpdmReturn(LIBSPDM_STATUS_SPDM_NOT_SUPPORTED);
            }

            copyBuffer(ByteBuffer.wrap(possibleResponse.get()), response, responseSize);
            return new LibSpdmReturn(LIBSPDM_STATUS_SUCCESS);
        } catch (Exception e) {
            log.error("Receiving message failed: {}", e.getMessage());
            log.debug("Stacktrace: ", e);
            return new LibSpdmReturn(LIBSPDM_STATUS_SPDM_INTERNAL_EXCEPTION);
        }
    }

    public LibSpdmReturn spdmDeviceAcquireSenderBuffer(Pointer spdmContext,
                                                       PointerByReference msgBufPtr) {
        try {
            nativeMemoryHandler.acquireSenderBuffer(msgBufPtr);
            return new LibSpdmReturn(LIBSPDM_STATUS_SUCCESS);
        } catch (Exception e) {
            log.error("Acquire sender buffer failed: {}", e.getMessage());
            log.debug("Stacktrace: ", e);
            return new LibSpdmReturn(LIBSPDM_STATUS_SPDM_INTERNAL_EXCEPTION);
        }
    }

    public void spdmDeviceReleaseSenderBuffer(Pointer spdmContext, Pointer msgBufPtr) {
        try {
            nativeMemoryHandler.releaseSenderBuffer();
        } catch (Exception e) {
            throw new SpdmRuntimeException("Release sender buffer failed.", e);
        }
    }

    public LibSpdmReturn spdmDeviceAcquireReceiverBuffer(Pointer spdmContext,
                                                         PointerByReference msgBufPtr) {
        try {
            nativeMemoryHandler.acquireReceiverBuffer(msgBufPtr);
            return new LibSpdmReturn(LIBSPDM_STATUS_SUCCESS);
        } catch (Exception e) {
            log.error("Acquire receiver buffer failed: {}", e.getMessage());
            log.debug("Stacktrace: ", e);
            return new LibSpdmReturn(LIBSPDM_STATUS_SPDM_INTERNAL_EXCEPTION);
        }
    }

    public void spdmDeviceReleaseReceiverBuffer(Pointer spdmContext, Pointer msgBufPtr) {
        try {
            nativeMemoryHandler.releaseReceiverBuffer();
        } catch (Exception e) {
            throw new SpdmRuntimeException("Release receiver buffer failed.", e);
        }
    }
}

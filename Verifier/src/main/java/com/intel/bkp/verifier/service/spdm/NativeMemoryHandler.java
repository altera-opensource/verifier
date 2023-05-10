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

import com.intel.bkp.verifier.exceptions.VerifierRuntimeException;
import com.sun.jna.Memory;
import com.sun.jna.Pointer;
import com.sun.jna.ptr.PointerByReference;
import lombok.Getter;
import lombok.Setter;

import static com.intel.bkp.verifier.jna.model.SpdmConstants.LIBSPDM_SENDER_RECEIVE_BUFFER_SIZE;

@Getter
@Setter
public class NativeMemoryHandler {

    private static NativeMemoryHandler INSTANCE = null;

    private final Memory senderBuffer;

    private final Memory receiverBuffer;

    private boolean senderBufferAcquired = false;
    private boolean receiverBufferAcquired = false;
    private byte[] response;

    static NativeMemoryHandler getInstance() {
        if (INSTANCE == null) {
            INSTANCE = new NativeMemoryHandler();
        }
        return INSTANCE;
    }

    private NativeMemoryHandler() {
        this(new Memory(LIBSPDM_SENDER_RECEIVE_BUFFER_SIZE), new Memory(LIBSPDM_SENDER_RECEIVE_BUFFER_SIZE));
    }

    NativeMemoryHandler(Memory senderBuffer, Memory receiverBuffer) {
        this.senderBuffer = senderBuffer;
        this.receiverBuffer = receiverBuffer;
    }

    void acquireSenderBuffer(Pointer maxMsgSize, PointerByReference msgBufPtr) {
        verifyIfBufferIsReleased(senderBufferAcquired);
        zeroizeBuffer(senderBuffer);
        acquireBuffer(maxMsgSize, msgBufPtr, senderBuffer);
        senderBufferAcquired = true;
    }

    void acquireReceiverBuffer(Pointer maxMsgSize, PointerByReference msgBufPtr) {
        verifyIfBufferIsReleased(receiverBufferAcquired);
        zeroizeBuffer(receiverBuffer);
        acquireBuffer(maxMsgSize, msgBufPtr, receiverBuffer);
        receiverBufferAcquired = true;
    }

    void releaseSenderBuffer() {
        verifyIfBufferIsAcquired(senderBufferAcquired);
        senderBufferAcquired = false;
    }

    void releaseReceiverBuffer() {
        verifyIfBufferIsAcquired(receiverBufferAcquired);
        receiverBufferAcquired = false;
    }

    private static void verifyIfBufferIsReleased(boolean bufferAcquired) {
        if (bufferAcquired) {
            throw new VerifierRuntimeException("Buffer is already acquired.");
        }
    }

    private static void verifyIfBufferIsAcquired(boolean bufferAcquired) {
        if (!bufferAcquired) {
            throw new VerifierRuntimeException("Buffer was not acquired.");
        }
    }

    private static void acquireBuffer(Pointer maxMsgSize, PointerByReference msgBufPtr, Memory buffer) {
        maxMsgSize.setLong(0, buffer.size());
        msgBufPtr.setValue(buffer);
    }

    private static void zeroizeBuffer(Memory buffer) {
        buffer.clear();
    }
}

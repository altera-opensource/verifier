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
import com.sun.jna.Memory;
import com.sun.jna.ptr.PointerByReference;
import lombok.Getter;
import lombok.Setter;

import static com.intel.bkp.protocol.spdm.jna.model.SpdmConstants.LIBSPDM_SENDER_RECEIVE_BUFFER_SIZE;

@Getter
@Setter
public class NativeMemoryHandler {

    private final Memory senderBuffer;

    private final Memory receiverBuffer;

    private boolean senderBufferAcquired = false;
    private boolean receiverBufferAcquired = false;

    public NativeMemoryHandler() {
        this(new Memory(LIBSPDM_SENDER_RECEIVE_BUFFER_SIZE), new Memory(LIBSPDM_SENDER_RECEIVE_BUFFER_SIZE));
    }

    NativeMemoryHandler(Memory senderBuffer, Memory receiverBuffer) {
        this.senderBuffer = senderBuffer;
        this.receiverBuffer = receiverBuffer;
    }

    void acquireSenderBuffer(PointerByReference msgBufPtr) throws BufferOperationFailed {
        verifyIfBufferIsReleased(senderBufferAcquired);
        zeroizeBuffer(senderBuffer);
        acquireBuffer(msgBufPtr, senderBuffer);
        senderBufferAcquired = true;
    }

    void acquireReceiverBuffer(PointerByReference msgBufPtr) throws BufferOperationFailed {
        verifyIfBufferIsReleased(receiverBufferAcquired);
        zeroizeBuffer(receiverBuffer);
        acquireBuffer(msgBufPtr, receiverBuffer);
        receiverBufferAcquired = true;
    }

    void releaseSenderBuffer() throws BufferOperationFailed {
        verifyIfBufferIsAcquired(senderBufferAcquired);
        senderBufferAcquired = false;
    }

    void releaseReceiverBuffer() throws BufferOperationFailed {
        verifyIfBufferIsAcquired(receiverBufferAcquired);
        receiverBufferAcquired = false;
    }

    private static void verifyIfBufferIsReleased(boolean bufferAcquired) throws BufferOperationFailed {
        if (bufferAcquired) {
            throw new BufferOperationFailed("Buffer is already acquired.");
        }
    }

    private static void verifyIfBufferIsAcquired(boolean bufferAcquired) throws BufferOperationFailed {
        if (!bufferAcquired) {
            throw new BufferOperationFailed("Buffer requested to release but it was not acquired.");
        }
    }

    private static void acquireBuffer(PointerByReference msgBufPtr, Memory buffer) {
        msgBufPtr.setValue(buffer);
    }

    private static void zeroizeBuffer(Memory buffer) {
        buffer.clear();
    }
}

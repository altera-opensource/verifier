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
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;

@ExtendWith(MockitoExtension.class)
class NativeMemoryHandlerTest {

    @Mock
    private Memory senderBuffer;

    @Mock
    private Memory receiverBuffer;

    @Mock
    private Pointer maxMsgSize;

    @Mock
    private PointerByReference msgBufPtr;

    private NativeMemoryHandler sut;

    @BeforeEach
    void setUp() {
        sut = new NativeMemoryHandler(senderBuffer, receiverBuffer);
    }

    @Test
    void acquireSenderBuffer_bufferNotPreviouslyAcquired_Success() {
        // given
        sut.setSenderBufferAcquired(false);

        // when
        sut.acquireSenderBuffer(maxMsgSize, msgBufPtr);

        // then
        verify(senderBuffer).clear();
        verify(senderBuffer).size();
        verify(msgBufPtr).setValue(senderBuffer);
        assertTrue(sut.isSenderBufferAcquired());
    }

    @Test
    void acquireReceiverBuffer_bufferNotPreviouslyAcquired_Success() {
        // given
        sut.setReceiverBufferAcquired(false);

        // when
        sut.acquireReceiverBuffer(maxMsgSize, msgBufPtr);

        // then
        verify(receiverBuffer).clear();
        verify(receiverBuffer).size();
        verify(msgBufPtr).setValue(receiverBuffer);
        assertTrue(sut.isReceiverBufferAcquired());
    }

    @Test
    void acquireSenderBuffer_bufferWasAlreadyAcquired_Throws() {
        // given
        sut.setSenderBufferAcquired(true);

        // when-then
        assertThrows(VerifierRuntimeException.class, () -> sut.acquireSenderBuffer(maxMsgSize, msgBufPtr));

        // then
        verify(senderBuffer, never()).clear();
        verify(senderBuffer, never()).size();
        verify(msgBufPtr, never()).setValue(any());
    }

    @Test
    void acquireReceiverBuffer_bufferWasAlreadyAcquired_Throws() {
        // given
        sut.setReceiverBufferAcquired(true);

        // when-then
        assertThrows(VerifierRuntimeException.class, () -> sut.acquireReceiverBuffer(maxMsgSize, msgBufPtr));

        // then
        verify(receiverBuffer, never()).clear();
        verify(receiverBuffer, never()).size();
        verify(msgBufPtr, never()).setValue(any());
    }

    @Test
    void releaseSenderBuffer_bufferWasPreviouslyAcquired_Success() {
        // given
        sut.setSenderBufferAcquired(true);

        // when
        sut.releaseSenderBuffer();

        // then
        assertFalse(sut.isSenderBufferAcquired());
    }

    @Test
    void releaseReceiverBuffer_bufferWasPreviouslyAcquired_Success() {
        // given
        sut.setReceiverBufferAcquired(true);

        // when
        sut.releaseReceiverBuffer();

        // then
        assertFalse(sut.isReceiverBufferAcquired());
    }

    @Test
    void releaseSenderBuffer_bufferWasNotYetAcquired_Throws() {
        // given
        sut.setSenderBufferAcquired(false);

        // when-then
        assertThrows(VerifierRuntimeException.class, () -> sut.releaseSenderBuffer());
    }

    @Test
    void releaseReceiverBuffer_bufferWasNotYetAcquired_Throws() {
        // given
        sut.setReceiverBufferAcquired(false);

        // when-then
        assertThrows(VerifierRuntimeException.class, () -> sut.releaseReceiverBuffer());
    }
}

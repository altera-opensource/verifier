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

import com.intel.bkp.protocol.spdm.exceptions.SpdmCommandFailedException;
import com.intel.bkp.protocol.spdm.exceptions.SpdmNotSupportedException;
import com.sun.jna.Memory;
import com.sun.jna.ptr.PointerByReference;
import org.junit.jupiter.api.Test;

import java.nio.ByteBuffer;

import static com.intel.bkp.protocol.spdm.jna.model.SpdmConstants.LIBSPDM_STATUS_SPDM_INTERNAL_EXCEPTION;
import static com.intel.bkp.protocol.spdm.jna.model.SpdmConstants.LIBSPDM_STATUS_SPDM_NOT_SUPPORTED;
import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

class SpdmUtilsTest {

    private static final byte[] DATA = new byte[]{1, 2, 3, 4};
    private static final ByteBuffer SRC_BUFFER = ByteBuffer.wrap(DATA);

    @Test
    void copyBuffer_dstBufferLargerThanSrcBuffer_Success() {
        // given
        final int dstBufferLen = 100;

        try (Memory dstBuffer = createBuffer(dstBufferLen); Memory dstLenP = createBufferLenP(dstBuffer.size())) {
            final PointerByReference dstBufferP = new PointerByReference(dstBuffer);

            // when
            SpdmUtils.copyBuffer(SRC_BUFFER, dstBufferP, dstLenP);

            // then
            assertEquals(DATA.length, dstLenP.getLong(0));
            assertArrayEquals(DATA, dstBufferP.getValue().getByteArray(0, DATA.length));
        }
    }

    @Test
    void copyBuffer_dstBufferTooSmall_Success() {
        // given
        final int dstBufferLen = 2;

        try (Memory dstBuffer = createBuffer(dstBufferLen); Memory dstLenP = createBufferLenP(dstBuffer.size())) {
            final PointerByReference dstBufferP = new PointerByReference(dstBuffer);
            // when-then
            assertThrows(RuntimeException.class,
                () -> SpdmUtils.copyBuffer(SRC_BUFFER, dstBufferP, dstLenP));
        }
    }

    @Test
    void getBytes() {
        // given
        try (Memory data = createBuffer(DATA.length); Memory dataLenP = createBufferLenP(data.size())) {
            data.setByte(0, DATA[0]);
            data.setByte(1, DATA[1]);
            data.setByte(2, DATA[2]);
            data.setByte(3, DATA[3]);

            // when
            final byte[] result = SpdmUtils.getBytes(data, dataLenP);

            // then
            assertArrayEquals(DATA, result);
        }
    }

    @Test
    void throwOnError_Status0_Success() {
        // when-then
        assertDoesNotThrow(() -> SpdmUtils.throwOnError(0L));
    }

    @Test
    void throwOnError_StatusSpdmNotSupportedException_Throws() {
        // when-then
        assertThrows(SpdmNotSupportedException.class,
            () -> SpdmUtils.throwOnError(LIBSPDM_STATUS_SPDM_NOT_SUPPORTED));
    }

    @Test
    void throwOnError_StatusVerifierException_Throws() {
        // when-then
        final RuntimeException ex = assertThrows(RuntimeException.class,
            () -> SpdmUtils.throwOnError(LIBSPDM_STATUS_SPDM_INTERNAL_EXCEPTION));

        // then
        assertEquals("SPDM exception due to internal error with status: 0x800100FE", ex.getMessage());
    }

    @Test
    void throwOnError_StatusError_Throws() {
        // when-then
        final SpdmCommandFailedException ex = assertThrows(SpdmCommandFailedException.class,
            () -> SpdmUtils.throwOnError(1L));

        // then
        assertEquals("SPDM command failed with status: 0x01", ex.getMessage());
    }

    private static Memory createBuffer(int bufferLen) {
        return new Memory(bufferLen);
    }

    private static Memory createBufferLenP(long bufferLen) {
        Memory bufferLenP = new Memory(Long.BYTES);
        bufferLenP.setLong(0, bufferLen);
        return bufferLenP;
    }
}

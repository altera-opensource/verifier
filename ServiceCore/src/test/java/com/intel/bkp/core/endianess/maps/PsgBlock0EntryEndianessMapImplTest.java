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

package com.intel.bkp.core.endianess.maps;

import com.intel.bkp.core.endianess.EndianessActor;
import com.intel.bkp.core.endianess.EndianessStructureFields;
import com.intel.bkp.utils.ByteSwapOrder;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

class PsgBlock0EntryEndianessMapImplTest {

    @Test
    void populateServiceMap_Success() {
        // when
        PsgBlock0EntryEndianessMapImpl sut = new PsgBlock0EntryEndianessMapImpl(EndianessActor.SERVICE);

        // then
        Assertions.assertEquals(0, sut.getSize());
    }

    @Test
    void populateFirmwareMap_Success() {
        // when
        PsgBlock0EntryEndianessMapImpl sut = new PsgBlock0EntryEndianessMapImpl(EndianessActor.FIRMWARE);

        // then
        Assertions.assertEquals(ByteSwapOrder.CONVERT, sut.get(EndianessStructureFields.BLOCK0_ENTRY_MAGIC));
        Assertions.assertEquals(ByteSwapOrder.CONVERT, sut.get(EndianessStructureFields.BLOCK0_LENGTH_OFFSET));
        Assertions.assertEquals(ByteSwapOrder.CONVERT, sut.get(EndianessStructureFields.BLOCK0_DATA_LEN));
        Assertions.assertEquals(ByteSwapOrder.CONVERT, sut.get(EndianessStructureFields.BLOCK0_SIG_LEN));
        Assertions.assertEquals(ByteSwapOrder.CONVERT, sut.get(EndianessStructureFields.BLOCK0_SHA_LEN));
        Assertions.assertEquals(5, sut.getSize());
    }
}

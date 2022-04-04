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

package com.intel.bkp.core.psgcertificate;

import com.intel.bkp.core.endianess.EndianessActor;
import com.intel.bkp.core.endianess.EndianessStructureFields;
import com.intel.bkp.core.endianess.EndianessStructureType;
import com.intel.bkp.core.interfaces.IEndianessMap;
import com.intel.bkp.utils.ByteSwapOrder;
import lombok.Getter;
import lombok.Setter;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

import java.nio.ByteBuffer;
import java.util.HashMap;

import static com.intel.bkp.utils.ByteConverter.toBytes;
import static com.intel.bkp.utils.ByteSwapOrder.CONVERT;
import static com.intel.bkp.utils.ByteSwapOrder.NONE;

class PsgDataBuilderTest {

    private final PsgDataBuilderImpl sut = new PsgDataBuilderImpl();

    @Test
    void currentStructureMap() {
        // given
        sut.setBuilderType(EndianessStructureType.PUF_MANIFEST);

        // when
        final EndianessStructureType structureMap = sut.currentStructureMap();

        // then
        Assertions.assertEquals(sut.getBuilderType(), structureMap);
    }

    @Test
    void withActor() {
        // given
        EndianessActor expected = EndianessActor.FIRMWARE;

        // when
        sut.withActor(expected);

        // then
        Assertions.assertEquals(expected, sut.getActor());
    }

    @Test
    void changeActor_WithDifferentActor_Success() {
        // given
        sut.withActor(EndianessActor.SERVICE);
        EndianessActor expected = EndianessActor.FIRMWARE;

        // when
        sut.changeActor(expected);

        // then
        Assertions.assertEquals(expected, sut.getActor());
    }

    @Test
    void changeActor_WithSameActor_Success() {
        // given
        sut.withActor(EndianessActor.SERVICE);
        EndianessActor expected = EndianessActor.SERVICE;

        // when
        sut.changeActor(expected);

        // then
        Assertions.assertEquals(expected, sut.getActor());
    }

    @Test
    void changeActor_WithNotExistingStructureMap_ThrowsException() {
        // given
        PsgDataBuilderImpl sutLocal = new PsgDataBuilderImpl();
        sutLocal.setBuilderType(EndianessStructureType.PSG_BLOCK_0_ENTRY);
        // when-then
        Assertions.assertThrows(IllegalStateException.class,
            () -> sutLocal.convert(1, EndianessStructureFields.MANIFEST_MAGIC)
        );
    }

    @Test
    void convert_WithIntValueAndStructureName_Success() {
        // given
        int expected = 1;
        final byte[] intBytes = toBytes(expected);

        // when
        final byte[] actual = sut.convert(expected, EndianessStructureFields.MANIFEST_DEVICE_UNIQUE_ID);

        // then
        Assertions.assertArrayEquals(intBytes, actual);
    }

    @Test
    void testConvert_WithIntValue_Success() {
        // given
        int expected = 1;
        final byte[] intBytes = toBytes(expected);

        // when
        final byte[] actual = sut.convert(expected);

        // then
        Assertions.assertArrayEquals(intBytes, actual);
    }

    @Test
    void testConvert_WithLongValue_Success() {
        // given
        long expected = 1;
        final byte[] longInBytes = ByteBuffer.allocate(Long.BYTES).putLong(expected).array();

        // when
        final byte[] actual = sut.convert(expected);

        // then
        Assertions.assertArrayEquals(longInBytes, actual);
    }

    @Test
    void testConvert_WithShortValue_Success() {
        // given
        short testValue = 1;
        final byte[] expected = ByteBuffer.allocate(Short.BYTES).putShort(testValue).array();

        // when
        final byte[] actual = sut.convert(testValue);

        // then
        Assertions.assertArrayEquals(expected, actual);
    }

    @Test
    void testConvert_WithValueAndStructureName_Success() {
        // given
        long expected = 1;
        final byte[] longInBytes = ByteBuffer.allocate(Long.BYTES).putLong(expected).array();

        // when
        final byte[] actual = sut.convert(longInBytes, EndianessStructureFields.MANIFEST_DEVICE_UNIQUE_ID);

        // then
        Assertions.assertArrayEquals(longInBytes, actual);
    }

    @Test
    void convertInt_Success() {
        // given
        int expected = 1;

        // when
        final int actual = sut.convertInt(expected, EndianessStructureFields.MANIFEST_DEVICE_UNIQUE_ID);

        // then
        Assertions.assertEquals(expected, actual);
    }

    @Test
    void convertShort_WithConvertFieldValue_Success() {
        // given
        byte[] inputData = new byte[]{0x00, 0x20};

        // when
        final short actual = sut.convertShort(inputData, EndianessStructureFields.MANIFEST_MAGIC);

        // then
        Assertions.assertEquals(8192, actual);
    }

    @Test
    void convertShort_WithNotConvertFieldValue_Success() {
        // given
        byte[] inputData = new byte[]{0x20, 0x00};

        // when
        final short actual = sut.convertShort(inputData, EndianessStructureFields.REG_STRUCTURE_HELP_DATA);

        // then
        Assertions.assertEquals(8192, actual);
    }

    private class PsgDataBuilderImpl extends PsgDataBuilder<PsgDataBuilderImpl> {

        @Getter
        @Setter
        private EndianessStructureType builderType;

        public PsgDataBuilderImpl() {
            maps.put(EndianessStructureType.PUF_MANIFEST, new PsgDataBuilderTestMapImpl());
        }

        @Override
        public EndianessStructureType currentStructureMap() {
            if (builderType == null) {
                return EndianessStructureType.PUF_MANIFEST;
            } else {
                return builderType;
            }
        }

        @Override
        public PsgDataBuilderImpl withActor(EndianessActor actor) {
            changeActor(actor);
            return this;
        }

        @Override
        protected void initStructureMap(EndianessStructureType currentStructureType, EndianessActor currentActor) {
            maps.put(currentStructureType, new PsgDataBuilderTestMapImpl());
        }
    }

    public class PsgDataBuilderTestMapImpl implements IEndianessMap {

        private HashMap<EndianessStructureFields, ByteSwapOrder> map = new HashMap<>();

        public PsgDataBuilderTestMapImpl() {
            put(EndianessStructureFields.MANIFEST_MAGIC, CONVERT);
        }

        public void put(EndianessStructureFields key, ByteSwapOrder value) {
            map.put(key, value);
        }

        @Override
        public ByteSwapOrder get(EndianessStructureFields key) {
            return map.getOrDefault(key, NONE);
        }
    }
}

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

package com.intel.bkp.core.endianness;

import com.intel.bkp.core.interfaces.IEndiannessMap;
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

class EndiannessBuilderTest {

    private final EndiannessBuilderImpl sut = new EndiannessBuilderImpl();

    @Test
    void withActor_WithDifferentActor_Success() {
        // given
        sut.withActor(EndiannessActor.SERVICE);
        EndiannessActor expected = EndiannessActor.FIRMWARE;

        // when
        sut.withActor(expected);

        // then
        Assertions.assertEquals(expected, sut.getActor());
    }

    @Test
    void withActor_WithSameActor_Success() {
        // given
        sut.withActor(EndiannessActor.SERVICE);
        EndiannessActor expected = EndiannessActor.SERVICE;

        // when
        sut.withActor(expected);

        // then
        Assertions.assertEquals(expected, sut.getActor());
    }

    @Test
    void changeActor_WithNotExistingStructureMap_ThrowsException() {
        // given
        EndiannessBuilderNullableImpl sutLocal = new EndiannessBuilderNullableImpl();
        sutLocal.setBuilderType(EndiannessStructureType.PSG_BLOCK_0_ENTRY);
        // when-then
        Assertions.assertThrows(IllegalStateException.class,
            () -> sutLocal.convert(1, EndiannessStructureFields.MANIFEST_MAGIC)
        );
    }

    @Test
    void convert_WithIntValueAndStructureName_Success() {
        // given
        int expected = 1;
        final byte[] intBytes = toBytes(expected);

        // when
        final byte[] actual = sut.convert(expected, EndiannessStructureFields.MANIFEST_DEVICE_UNIQUE_ID);

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
        final byte[] actual = sut.convert(longInBytes, EndiannessStructureFields.MANIFEST_DEVICE_UNIQUE_ID);

        // then
        Assertions.assertArrayEquals(longInBytes, actual);
    }

    @Test
    void convertInt_Success() {
        // given
        int expected = 1;

        // when
        final int actual = sut.convertInt(expected, EndiannessStructureFields.MANIFEST_DEVICE_UNIQUE_ID);

        // then
        Assertions.assertEquals(expected, actual);
    }

    @Test
    void convertShort_WithConvertFieldValue_Success() {
        // given
        byte[] inputData = new byte[]{0x00, 0x20};

        // when
        final short actual = sut.convertShort(inputData, EndiannessStructureFields.MANIFEST_MAGIC);

        // then
        Assertions.assertEquals(8192, actual);
    }

    @Test
    void convertShort_WithNotConvertFieldValue_Success() {
        // given
        byte[] inputData = new byte[]{0x20, 0x00};

        // when
        final short actual = sut.convertShort(inputData, EndiannessStructureFields.REG_STRUCTURE_HELP_DATA);

        // then
        Assertions.assertEquals(8192, actual);
    }

    private class EndiannessBuilderImpl extends EndiannessBuilder<EndiannessBuilderImpl> {

        @Getter
        @Setter
        private EndiannessStructureType builderType;

        public EndiannessBuilderImpl() {
            super(EndiannessStructureType.PUF_MANIFEST);
        }

        @Override
        protected EndiannessBuilderImpl self() {
            return this;
        }

        @Override
        protected void initStructureMap(EndiannessStructureType currentStructureType, EndiannessActor currentActor) {
            maps.put(currentStructureType, new PsgDataBuilderTestMapImpl());
        }
    }

    private class EndiannessBuilderNullableImpl extends EndiannessBuilder<EndiannessBuilderNullableImpl> {

        @Getter
        @Setter
        private EndiannessStructureType builderType;

        public EndiannessBuilderNullableImpl() {
            super(null);
        }

        @Override
        protected EndiannessBuilderNullableImpl self() {
            return this;
        }

        @Override
        protected void initStructureMap(EndiannessStructureType currentStructureType, EndiannessActor currentActor) {
        }
    }

    public class PsgDataBuilderTestMapImpl implements IEndiannessMap {

        private HashMap<EndiannessStructureFields, ByteSwapOrder> map = new HashMap<>();

        public PsgDataBuilderTestMapImpl() {
            put(EndiannessStructureFields.MANIFEST_MAGIC, CONVERT);
        }

        public void put(EndiannessStructureFields key, ByteSwapOrder value) {
            map.put(key, value);
        }

        @Override
        public ByteSwapOrder get(EndiannessStructureFields key) {
            return map.getOrDefault(key, NONE);
        }
    }
}

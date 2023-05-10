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

package com.intel.bkp.core.endianness;

import com.intel.bkp.core.decoding.EncoderDecoder;
import com.intel.bkp.core.decoding.IEncoderDecoder;
import com.intel.bkp.core.exceptions.ParseStructureException;
import com.intel.bkp.core.interfaces.IEndiannessMap;
import com.intel.bkp.core.interfaces.IStructure;
import com.intel.bkp.utils.ByteBufferSafe;
import com.intel.bkp.utils.ByteSwapOrder;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Spy;
import org.mockito.junit.jupiter.MockitoExtension;

import java.util.HashMap;
import java.util.Map;

import static com.intel.bkp.utils.ByteSwapOrder.CONVERT;
import static com.intel.bkp.utils.ByteSwapOrder.NONE;
import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.mockStatic;
import static org.mockito.Mockito.spy;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoMoreInteractions;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class StructureBuilderTest {

    @Spy
    private StructureTypeImpl structureTypeSpy = StructureTypeImpl.TEST_VALUE;

    @InjectMocks
    private StructureBuilderImpl sut;

    @Test
    void getBuilder_Success() {
        final var builderSpy = spy(new StructureBuilderImpl(StructureTypeImpl.TEST_VALUE));
        final var actor = EndiannessActor.FIRMWARE;
        final var data = new byte[]{1, 2, 3};

        // when
        final var result = StructureBuilder.getBuilder(() -> builderSpy, actor, data);

        // then
        assertEquals(builderSpy, result);
        verify(builderSpy).withActor(actor);
        verify(builderSpy).parse(data);
    }

    @Test
    void withActor_WithDifferentActor_Success() {
        // given
        verifyEndiannessMapSetOnce(sut.getActor());
        final EndiannessActor expected = getDifferentActor(sut.getActor());

        // when
        final var result = sut.withActor(expected);

        // then
        assertEquals(sut, result);
        assertEquals(expected, sut.getActor());
        verifyEndiannessMapSetOnce(expected);
    }

    @Test
    void withActor_WithSameActor_Success() {
        // given
        verifyEndiannessMapSetOnce(sut.getActor());
        final EndiannessActor expected = sut.getActor();

        // when
        final var result = sut.withActor(expected);

        // then
        assertEquals(sut, result);
        assertEquals(expected, sut.getActor());
        verifyEndiannessMapNotSetAnymore();
    }

    @Test
    void withEncoderDecoder_Success() {
        // given
        final EncoderDecoder expected = getDifferentEncoder(sut.getEncoderDecoder());

        // when
        final var result = sut.withEncoderDecoder(expected);

        // then
        assertEquals(sut, result);
        assertEquals(expected, sut.getEncoderDecoder());
    }

    @Test
    void parse_WithString_InvokesParseWithBytes() {
        // given
        final String data = "data";
        final byte[] decodedData = new byte[]{1, 2, 3};
        final var encoderDecoderMock = mock(EncoderDecoder.class);
        final var encoderDecoderInstanceMock = mock(IEncoderDecoder.class);
        when(encoderDecoderMock.getInstance()).thenReturn(encoderDecoderInstanceMock);
        when(encoderDecoderInstanceMock.decode(data)).thenReturn(decodedData);
        final var sutSpy = spy(new StructureBuilderImpl(StructureTypeImpl.TEST_VALUE));
        sutSpy.withEncoderDecoder(encoderDecoderMock);

        // when
        final var result = sutSpy.parse(data);

        // then
        verify(sutSpy).parse(decodedData);
        assertEquals(sutSpy, result);
    }

    @Test
    void parse_WithBytes_InvokesParseWithByteBufferSafe() {
        // given
        final byte[] data = new byte[]{1, 2, 3};
        final ByteBufferSafe buffer = mock(ByteBufferSafe.class);
        final var sutSpy = spy(new StructureBuilderImpl(StructureTypeImpl.TEST_VALUE));

        try (var byteBufferSafeStaticMock = mockStatic(ByteBufferSafe.class)) {
            when(ByteBufferSafe.wrap(data)).thenReturn(buffer);

            // when
            final var result = sutSpy.parse(data);

            // then
            verify(sutSpy).parse(buffer);
            assertEquals(sutSpy, result);
        }
    }

    @Test
    void convert_WithAbsentEndiannessMap_ThrowsException() {
        // given
        final var sutLocal = new StructureBuilderImpl(null);

        // when-then
        final var ex = assertThrows(IllegalStateException.class,
            () -> sutLocal.convert(1, StructureFieldImpl.FIELD_TO_CONVERT)
        );

        //then
        assertEquals("Endianness map is absent.", ex.getMessage());
    }

    @Test
    void convert_WithIntValue_WithNotConvertedField_Success() {
        // given
        int value = 1;
        final byte[] expectedBytes = new byte[]{0, 0, 0, 1};

        // when
        final byte[] actual = sut.convert(value, StructureFieldImpl.FIELD_NOT_CONVERTED);

        // then
        assertArrayEquals(expectedBytes, actual);
    }

    @Test
    void convert_WithIntValue_WithConvertedField_Success() {
        // given
        int value = 1;
        final byte[] expectedBytes = new byte[]{1, 0, 0, 0};

        // when
        final byte[] actual = sut.convert(value, StructureFieldImpl.FIELD_TO_CONVERT);

        // then
        assertArrayEquals(expectedBytes, actual);
    }

    @Test
    void convert_WithBytesValue_WithNotConvertedField_Success() {
        // given
        byte[] value = new byte[]{1, 2, 3, 4, 5, 6, 7, 8};

        // when
        final byte[] actual = sut.convert(value, StructureFieldImpl.FIELD_NOT_CONVERTED);

        // then
        assertArrayEquals(value, actual);
    }

    @Test
    void convert_WithBytesValue_WithConvertedField_Success() {
        // given
        byte[] value = new byte[]{1, 2, 3, 4, 5, 6, 7, 8};
        byte[] expected = new byte[]{4, 3, 2, 1, 8, 7, 6, 5};

        // when
        final byte[] actual = sut.convert(value, StructureFieldImpl.FIELD_TO_CONVERT);

        // then
        assertArrayEquals(expected, actual);
    }

    @Test
    void convertInt_WithNotConvertedField_Success() {
        // given
        int value = 1;

        // when
        final int actual = sut.convertInt(value, StructureFieldImpl.FIELD_NOT_CONVERTED);

        // then
        assertEquals(value, actual);
    }

    @Test
    void convertInt_WithConvertedField_Success() {
        // given
        int value = 1;
        int expected = 16777216;

        // when
        final int actual = sut.convertInt(value, StructureFieldImpl.FIELD_TO_CONVERT);

        // then
        assertEquals(expected, actual);
    }

    @Test
    void convertShort_WithBytesValue_WithConvertedField_Success() {
        // given
        byte[] inputData = new byte[]{0x00, 0x20};

        // when
        final short actual = sut.convertShort(inputData, StructureFieldImpl.FIELD_TO_CONVERT);

        // then
        assertEquals(8192, actual);
    }

    @Test
    void convertShort_WithBytesValue_WithNotConvertedField_Success() {
        // given
        byte[] inputData = new byte[]{0x20, 0x00};
        final int expected = 8192;

        // when
        final short actual = sut.convertShort(inputData, StructureFieldImpl.FIELD_NOT_CONVERTED);

        // then
        assertEquals(expected, actual);
    }

    @Test
    void convertShort_WithShort_WithConvertedField_Success() {
        // given
        final short value = 32;
        final short expected = 8192;

        // when
        final short actual = sut.convertShort(value, StructureFieldImpl.FIELD_TO_CONVERT);

        // then
        assertEquals(expected, actual);
    }

    @Test
    void convertShort_WithShortValue_WithNotConvertedField_Success() {
        // given
        final short value = 8192;

        // when
        final short actual = sut.convertShort(value, StructureFieldImpl.FIELD_NOT_CONVERTED);

        // then
        assertEquals(value, actual);
    }

    private void verifyEndiannessMapSetOnce(EndiannessActor actor) {
        verify(structureTypeSpy).getEndiannessMap(actor);
        verifyEndiannessMapNotSetAnymore();
    }

    private EndiannessActor getDifferentActor(EndiannessActor actor) {
        return EndiannessActor.SERVICE == actor ? EndiannessActor.FIRMWARE : EndiannessActor.SERVICE;
    }

    private EncoderDecoder getDifferentEncoder(EncoderDecoder encoderDecoder) {
        return EncoderDecoder.HEX == encoderDecoder ? EncoderDecoder.BASE32 : EncoderDecoder.HEX;
    }

    private void verifyEndiannessMapNotSetAnymore() {
        verifyNoMoreInteractions(structureTypeSpy);
    }

    private enum StructureFieldImpl implements IStructureField {
        FIELD_TO_CONVERT, FIELD_NOT_CONVERTED;
    }

    private enum StructureTypeImpl implements IStructureType {
        TEST_VALUE;

        @Override
        public IEndiannessMap getEndiannessMap(EndiannessActor actor) {
            return new EndiannessMapTestImpl();
        }

        static class EndiannessMapTestImpl implements IEndiannessMap {

            private Map<IStructureField, ByteSwapOrder> map = new HashMap<>();

            public EndiannessMapTestImpl() {
                put(StructureFieldImpl.FIELD_TO_CONVERT, CONVERT);
            }

            public void put(IStructureField key, ByteSwapOrder value) {
                map.put(key, value);
            }

            @Override
            public ByteSwapOrder get(IStructureField key) {
                return map.getOrDefault(key, NONE);
            }
        }
    }

    private static class StructureBuilderImpl
        extends StructureBuilder<StructureBuilderImpl, StructureImpl> {

        public StructureBuilderImpl(IStructureType structureType) {
            super(structureType);
        }

        @Override
        public StructureBuilderImpl parse(ByteBufferSafe buffer) throws ParseStructureException {
            return self();
        }

        @Override
        public StructureImpl build() {
            return null;
        }

        @Override
        public StructureBuilderImpl self() {
            return this;
        }
    }

    private static class StructureImpl implements IStructure {

        @Override
        public byte[] array() {
            return new byte[0];
        }
    }
}

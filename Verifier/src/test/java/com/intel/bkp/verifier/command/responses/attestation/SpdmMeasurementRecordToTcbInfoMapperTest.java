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

package com.intel.bkp.verifier.command.responses.attestation;

import com.intel.bkp.core.endianess.EndianessActor;
import com.intel.bkp.fpgacerts.dice.tcbinfo.FwIdField;
import com.intel.bkp.fpgacerts.dice.tcbinfo.TcbInfo;
import com.intel.bkp.fpgacerts.dice.tcbinfo.TcbInfoField;
import com.intel.bkp.utils.ByteBufferSafe;
import com.intel.bkp.utils.ByteSwap;
import com.intel.bkp.utils.ByteSwapOrder;
import com.intel.bkp.verifier.exceptions.VerifierRuntimeException;
import com.intel.bkp.verifier.model.evidence.SectionType;
import com.intel.bkp.verifier.model.evidence.SpdmMeasurementRecordHeader;
import com.intel.bkp.verifier.model.evidence.SpdmMeasurementRecordHeaderBuilder;
import org.junit.jupiter.api.Test;

import java.nio.ByteBuffer;
import java.util.Random;

import static com.intel.bkp.utils.HexConverter.fromHex;
import static com.intel.bkp.utils.HexConverter.toHex;
import static com.intel.bkp.verifier.command.responses.attestation.SpdmMeasurementRecordToTcbInfoMapper.PR_SECTION_INDEX_SHIFT;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/*
    Sample MEASUREMENT taken from SPDM simulator
*/
class SpdmMeasurementRecordToTcbInfoMapperTest {

    private static final int DMTF_MEASUREMENT_HEADER_SIZE = SpdmDmtfMeasurementRecordHeaderBuilder.HEADER_SIZE;

    @Test
    void map_WithDmtfMeasurement_DeviceStateSection_Success() {
        // given
        final String measurement = "01010b008208000000000002000000";
        final String expectedVendorInfo = "0000000002000000";
        final ByteBufferSafe buffer = getBuffer(measurement);
        final SpdmMeasurementRecordHeader header = new SpdmMeasurementRecordHeaderBuilder().parse(buffer).build();

        // when
        final TcbInfo result = new SpdmMeasurementRecordToTcbInfoMapper().map(header, buffer);

        // then
        assertIgnoreCase(expectedVendorInfo, result.get(TcbInfoField.VENDOR_INFO).get().toString());
        assertEquals(0, buffer.remaining());
    }

    @Test
    void map_WithDmtfMeasurement_IoSection_Success() {
        // given
        final String measurement =
            "02013300013000d83677e64f512f69164a5c00ddfc14eb9d4a40edb11244235ab6a3de738f3b6c7e3f022c765b5d81"
                + "fa7afd257d3337bf";
        final String expectedHash =
            "d83677e64f512f69164a5c00ddfc14eb9d4a40edb11244235ab6a3de738f3b6c7e3f022c765b5d81fa7afd257d3337bf";
        final ByteBufferSafe buffer = getBuffer(measurement);
        final SpdmMeasurementRecordHeader header =
            new SpdmMeasurementRecordHeaderBuilder().parse(buffer).build();

        // when
        final TcbInfo result = new SpdmMeasurementRecordToTcbInfoMapper().map(header, buffer);

        // then
        assertFwId(expectedHash, result);
        assertEquals(0, buffer.remaining());
    }

    @Test
    void map_WithIoSectionButFwIdHashAlgNotSupported_Throws() {
        // given
        final String measurement =
            "02013300013000d83677e64f512f69164a5c00ddfc14eb9d4a40edb11244235ab6a3de738f3b6c7e3f022c765b5d81"
                + "fa7afd257d3337bf";
        final ByteBufferSafe buffer = getBuffer(measurement);

        final SpdmMeasurementRecordHeaderBuilder headerBuilder = new SpdmMeasurementRecordHeaderBuilder().parse(buffer);
        final short invalidMeasurementSize = 10;
        headerBuilder.setMeasurementSize(invalidMeasurementSize);
        final SpdmMeasurementRecordHeader header = headerBuilder.build();

        // when-then
        final VerifierRuntimeException exception = assertThrows(VerifierRuntimeException.class,
            () -> new SpdmMeasurementRecordToTcbInfoMapper().map(header, buffer));

        // then
        assertEquals("Parsing FwIdHashALg failed.", exception.getMessage());
    }

    @Test
    void map_WithDmtfMeasurement_PrSection_Success() {
        // given
        final byte[] measurementArray = new byte[UserDesignMeasurementRecord.DEFAULT_MEASUREMENT_SIZE];
        new Random().nextBytes(measurementArray);
        final String expectedMeasurement = toHex(measurementArray);

        final int index = SectionType.MIN_PR_INDEX;
        final short size = (short) (expectedMeasurement.length() / 2);
        final SpdmMeasurementRecordHeader header = prepareHeaderWithDmtfMeasurement(index, size);
        final byte[] dmtfHeader = prepareDmtfHeader(SectionType.PR.getType(), size).array();
        final ByteBufferSafe buffer = getBufferWithHeader(dmtfHeader, measurementArray);

        // when
        final TcbInfo result = new SpdmMeasurementRecordToTcbInfoMapper().map(header, buffer);

        // then
        assertFwId(expectedMeasurement, result);
        assertEquals(0, buffer.remaining());
    }

    @Test
    void map_NotDmtf_Skips() {
        // given
        final String measurement = "01020304";
        final SpdmMeasurementRecordHeader header = prepareHeaderNotDmtf((short) (measurement.length() / 2));
        final ByteBufferSafe buffer = getBuffer(measurement);

        // when
        final TcbInfo result = new SpdmMeasurementRecordToTcbInfoMapper().map(header, buffer);

        // then
        assertTrue(result.isEmpty());
        assertEquals(0, buffer.remaining());
    }

    @Test
    void map_DmtfMeasurementButUnknownSection_Skips() {
        // given
        final String measurement =
            "fd016d00846a00db0000000100000000a1009803a4004b6086480186f84d010f04010169696e74656c2e636f6d0"
                + "30220811801a4004b6086480186f84d010f04020169696e74656c2e636f6d030220811802a4004b608648"
                + "0186f84d010f04030169696e74656c2e636f6d030220811803";
        final ByteBufferSafe buffer = getBuffer(measurement);
        final SpdmMeasurementRecordHeader header =
            new SpdmMeasurementRecordHeaderBuilder().parse(buffer).build();

        // when
        final TcbInfo result = new SpdmMeasurementRecordToTcbInfoMapper().map(header, buffer);

        // then
        assertTrue(result.isEmpty());
        assertEquals(0, buffer.remaining());
    }

    @Test
    void getPrSectionIndex_With0x01() {
        // given
        final int expectedPrSectionIndex = 0x01; // comes from RIM as little endian 0x010000000
        final SpdmMeasurementRecordHeader header = prepareHeader(expectedPrSectionIndex);

        // when
        final int result = new SpdmMeasurementRecordToTcbInfoMapper().getPrSectionIndex(header);

        // then
        assertEquals(ByteSwap.getSwappedInt(expectedPrSectionIndex, ByteSwapOrder.B2L), result);
    }

    @Test
    void getPrSectionIndex_With0x5F() {
        // given
        final int expectedPrSectionIndex = 0x1F;  // comes from RIM as little endian 0x1F0000000
        final SpdmMeasurementRecordHeader header = prepareHeader(expectedPrSectionIndex);

        // when
        final int result = new SpdmMeasurementRecordToTcbInfoMapper().getPrSectionIndex(header);

        // then
        assertEquals(ByteSwap.getSwappedInt(expectedPrSectionIndex, ByteSwapOrder.B2L), result);
    }

    @Test
    void getMeasurementSize_WithDmtf_ReturnsMeasurementSizeMinusHeaderSize() {
        // given
        final short expectedMeasurementSize = 8;
        final SpdmMeasurementRecordHeader header = prepareHeaderWithDmtfMeasurement(1, expectedMeasurementSize);

        // when
        final int result = new SpdmMeasurementRecordToTcbInfoMapper().getMeasurementSize(header);

        // then
        assertEquals(expectedMeasurementSize, result);
    }

    @Test
    void getMeasurementSize_NoDmtf_ReturnsSameMeasurementSize() {
        // given
        final short expectedMeasurementSize = 8;
        final SpdmMeasurementRecordHeader header = prepareHeaderNotDmtf(expectedMeasurementSize);

        // when
        final int result = new SpdmMeasurementRecordToTcbInfoMapper().getMeasurementSize(header);

        // then
        assertEquals(expectedMeasurementSize, result);
    }

    private static SpdmMeasurementRecordHeader prepareHeaderWithDmtfMeasurement(int sectionType,
                                                                                short measurementSize) {
        final SpdmMeasurementRecordHeader header = new SpdmMeasurementRecordHeader();
        header.setIndex((byte) sectionType);
        header.setMeasurementSpec((byte) 1);
        header.setMeasurementSize((short) (measurementSize + DMTF_MEASUREMENT_HEADER_SIZE));
        return header;
    }

    private SpdmDmtfMeasurementHeader prepareDmtfHeader(int sectionType, short size) {
        final SpdmDmtfMeasurementRecordHeaderBuilder builder = new SpdmDmtfMeasurementRecordHeaderBuilder();
        builder.setType((byte) sectionType);
        builder.setSize(size);
        return builder.withActor(EndianessActor.FIRMWARE).build();
    }

    private static SpdmMeasurementRecordHeader prepareHeaderNotDmtf(short measurementSize) {
        final SpdmMeasurementRecordHeader header = new SpdmMeasurementRecordHeader();
        header.setMeasurementSpec((byte) 0x0);
        header.setMeasurementSize(measurementSize);
        return header;
    }

    private static SpdmMeasurementRecordHeader prepareHeader(int expectedPrSectionIndex) {
        final SpdmMeasurementRecordHeader header = new SpdmMeasurementRecordHeader();
        header.setIndex((byte) (PR_SECTION_INDEX_SHIFT + expectedPrSectionIndex - 1));
        return header;
    }

    private static ByteBufferSafe getBuffer(String measurement) {
        return ByteBufferSafe.wrap(fromHex(measurement));
    }

    private static ByteBufferSafe getBufferWithHeader(byte[] dmtfHeader, byte[] measurement) {
        return ByteBufferSafe.wrap(
            ByteBuffer.allocate(dmtfHeader.length + measurement.length)
                .put(dmtfHeader)
                .put(measurement)
                .array()
        );
    }

    private static void assertFwId(String expectedMeasurement, TcbInfo result) {
        assertIgnoreCase(expectedMeasurement, ((FwIdField) result.get(TcbInfoField.FWIDS).get()).getDigest());
    }

    private static void assertIgnoreCase(String expectedValue, String actualValue) {
        assertEquals(expectedValue.toLowerCase(), actualValue.toLowerCase());
    }
}

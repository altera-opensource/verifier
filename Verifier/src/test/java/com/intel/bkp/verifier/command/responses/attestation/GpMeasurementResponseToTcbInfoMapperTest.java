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

import com.intel.bkp.core.endianness.EndiannessActor;
import com.intel.bkp.fpgacerts.dice.tcbinfo.FwIdField;
import com.intel.bkp.fpgacerts.dice.tcbinfo.TcbInfoMeasurement;
import com.intel.bkp.verifier.Utils;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.util.List;

class GpMeasurementResponseToTcbInfoMapperTest {

    private static final String TEST_FOLDER = "responses/";
    private static final String MEASUREMENTS_RSP_FILENAME = "measurements_response_stratix10.bin";
    private static final String MEASUREMENTS_RSP_AGILEX_FILENAME = "measurements_response_agilex.bin";

    // This data come from parsing and editing the measurement_response_stratix10/agilex.bin in HEX EDITOR
    // Additional data for Agilex added manually in Hex Editor
    // Signature and MAC are invalid for both files
    private static final String EXPECTED_DEVICE_DATA_STRATIX = "0002000002000000";
    private static final String EXPECTED_DEVICE_DATA_AGILEX = "0000000003000000";
    private static final String EXPECTED_IO_DATA = "664AAD52B52B717A2597CBFE0D1BF43FD5860DB48EFEDA21C9C2D892828BA70BE6"
        + "1162A273A8A7156337CD8343CA24FE";
    private static final String EXPECTED_CORE_DATA = "5D04018373C58AB309644118599094F7A5CF759F9C2F14759B2435F3387F4DA"
        + "F9B05DBF6BC25D215F16BC81FB93F9F2B";

    private static final String EXPECTED_PR1_DATA = "CBF9E12CDF8ED22F9752574E440A5964458AAEFFDE7533EF16368DE4551F9028"
        + "2AC2A890BE1C42796B3385686AC3CB81";
    private static final String EXPECTED_PR2_DATA = "EDCB0F4721E6578D900E4C24AD4B19E194AB6C87F8243BFC6B11754DD8B0BBDE"
        + "4F30B1D18197932B6376DA004DCD97C4";

    private static final int SECTION_INDEX_PR1 = 16777216;
    private static final int SECTION_INDEX_PR2 = 33554432;
    private static final int EXPECTED_RECORDS_SIZE_S10 = 4;
    private static final int EXPECTED_RECORDS_SIZE_AGILEX = 5;

    private static GetMeasurementResponse responseS10;
    private static GetMeasurementResponse responseAgilex;

    @BeforeAll
    static void init() throws Exception {
        responseS10 = readResponse(MEASUREMENTS_RSP_FILENAME);
        responseAgilex = readResponse(MEASUREMENTS_RSP_AGILEX_FILENAME);
    }

    private static GetMeasurementResponse readResponse(String filename) throws Exception {
        final byte[] response = Utils.readFromResources(TEST_FOLDER, filename);
        return new GetMeasurementResponseBuilder()
            .withActor(EndiannessActor.FIRMWARE)
            .parse(response)
            .withActor(EndiannessActor.SERVICE)
            .build();
    }

    private GpMeasurementResponseToTcbInfoMapper sut;

    @BeforeEach
    void setUp() {
        sut = new GpMeasurementResponseToTcbInfoMapper();
    }

    @Test
    void map_Stratix10() {
        // when
        final List<TcbInfoMeasurement> measurements = sut.map(responseS10);

        // then
        Assertions.assertEquals(EXPECTED_RECORDS_SIZE_S10, measurements.size());

        assertDeviceStateSectionStratix(measurements);
        assertIoSection(measurements);
        assertCoreSection(measurements);
        assertPrSectionStratix(measurements);
    }

    @Test
    void map_Agilex() {
        // when
        final List<TcbInfoMeasurement> measurements = sut.map(responseAgilex);

        // then
        Assertions.assertEquals(EXPECTED_RECORDS_SIZE_AGILEX, measurements.size());

        assertDeviceStateSectionAgilex(measurements);
        assertIoSection(measurements);
        assertCoreSection(measurements);
        assertPrSectionsAgilex(measurements);
    }

    private void assertDeviceStateSectionStratix(List<TcbInfoMeasurement> measurements) {
        final TcbInfoMeasurement deviceStateSection = measurements.get(0);
        Assertions.assertEquals(EXPECTED_DEVICE_DATA_STRATIX,
            deviceStateSection.getValue().getMaskedVendorInfo().get().getVendorInfo());
    }

    private void assertDeviceStateSectionAgilex(List<TcbInfoMeasurement> measurements) {
        final TcbInfoMeasurement deviceStateSection = measurements.get(0);
        Assertions.assertEquals(EXPECTED_DEVICE_DATA_AGILEX,
            deviceStateSection.getValue().getMaskedVendorInfo().get().getVendorInfo());
    }

    private void assertIoSection(List<TcbInfoMeasurement> measurements) {
        final TcbInfoMeasurement ioSection = measurements.get(1);
        Assertions.assertEquals(EXPECTED_IO_DATA, fwIdToHash(ioSection));
    }

    private void assertCoreSection(List<TcbInfoMeasurement> measurements) {
        final TcbInfoMeasurement coreSection = measurements.get(2);
        Assertions.assertEquals(EXPECTED_CORE_DATA, fwIdToHash(coreSection));
    }

    private void assertPrSectionStratix(List<TcbInfoMeasurement> measurements) {
        final TcbInfoMeasurement prSection1 = measurements.get(3);
        Assertions.assertEquals(EXPECTED_PR1_DATA, fwIdToHash(prSection1));
    }

    private void assertPrSectionsAgilex(List<TcbInfoMeasurement> measurements) {
        final TcbInfoMeasurement prSection1 = measurements.get(3);
        Assertions.assertEquals(EXPECTED_PR1_DATA, fwIdToHash(prSection1));
        Assertions.assertEquals(SECTION_INDEX_PR1, prSection1.getKey().getIndex());

        final TcbInfoMeasurement prSection2 = measurements.get(4);
        Assertions.assertEquals(EXPECTED_PR2_DATA, fwIdToHash(prSection2));
        Assertions.assertEquals(SECTION_INDEX_PR2, prSection2.getKey().getIndex());
    }

    private String fwIdToHash(TcbInfoMeasurement measurement) {
        final FwIdField field = measurement.getValue().getFwid()
            .orElseThrow(() -> new RuntimeException("Expected FwId field in TcbInfo, but it does not exist."));
        return field.getDigest();
    }
}

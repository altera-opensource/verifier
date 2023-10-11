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

package com.intel.bkp.command.responses.sigma;

import com.intel.bkp.core.endianness.EndiannessActor;
import com.intel.bkp.test.FileUtils;
import com.intel.bkp.utils.ByteBufferSafe;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.junit.jupiter.MockitoExtension;

import java.util.Arrays;
import java.util.Random;

import static com.intel.bkp.command.model.Magic.GET_MEASUREMENT_RSP;
import static com.intel.bkp.command.responses.sigma.DeviceFamilyFuseMap.FM568;
import static com.intel.bkp.command.responses.sigma.DeviceFamilyFuseMap.S10;
import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;

@ExtendWith(MockitoExtension.class)
class GetMeasurementResponseBuilderTest {

    private static final String TEST_FOLDER = "responses/";
    private static final String FILENAME_STRATIX_RESPONSE = "measurements_response_stratix10.bin";
    private static final String FILENAME_AGILEX_RESPONSE = "measurements_response_agilex.bin";

    private static final byte DEVICE_FAMILY_FUSE_MAP_S10 = S10.getByteFromOrdinal();
    private static final byte DEVICE_FAMILY_FUSE_MAP_FM568 = FM568.getByteFromOrdinal();

    private static final int EXPECTED_SDM_SESSION_ID = 1;
    private static final int EXPECTED_BLOCKS_NUM_S10 = 4;
    private static final int EXPECTED_RECORD_LEN_S10 = 184;
    private static final int EXPECTED_BLOCKS_NUM_AGILEX = 5;
    private static final int EXPECTED_RECORD_LEN_AGILEX = 240;

    private static byte[] measurementsResponseStratix;
    private static byte[] measurementsResponseAgilex;

    private final Random random = new Random();

    private final byte[] magic = new byte[Integer.BYTES];
    private final byte[] sdmSessionId = new byte[Integer.BYTES];
    private final byte[] deviceUniqueId = new byte[Long.BYTES];
    private final byte[] romVersionNum = new byte[Integer.BYTES];
    private final byte[] sdmFwBuildId = new byte[GetMeasurementResponseBuilder.SDM_FW_BUILD_ID_LEN];
    private final byte[] sdmFwSecurityVersionNum = new byte[Integer.BYTES];
    private final byte[] reserved = new byte[GetMeasurementResponseBuilder.RESERVED_LEN];
    private final byte[] publicEfuseValuesS10 = new byte[S10.getEfuseValuesFieldLen()];
    private final byte[] publicEfuseValuesFm568 = new byte[FM568.getEfuseValuesFieldLen()];
    private final byte[] deviceDhPubKey = new byte[GetMeasurementResponseBuilder.DH_PUB_KEY_LEN];
    private final byte[] verifierDhPubKey = new byte[GetMeasurementResponseBuilder.DH_PUB_KEY_LEN];
    private final byte[] cmfDescriptorHash = new byte[GetMeasurementResponseBuilder.CMF_DESCRIPTOR_HASH_LEN];
    private final byte[] reserved2 = new byte[GetMeasurementResponseBuilder.RESERVED2_LEN];
    private final byte numberOfMeasurementBlocks = 2;
    private final byte reserved3 = 0;
    private final short measurementRecordLen = 100;
    private final byte[] measurementRecord = new byte[measurementRecordLen];
    private final byte[] mac = new byte[GetMeasurementResponseBuilder.SHA_384_MAC_LEN];

    @BeforeAll
    static void init() throws Exception {
        measurementsResponseStratix = FileUtils.readFromResources(TEST_FOLDER, FILENAME_STRATIX_RESPONSE);
        measurementsResponseAgilex = FileUtils.readFromResources(TEST_FOLDER, FILENAME_AGILEX_RESPONSE);
    }

    @Test
    void parse_S10() {
        // when
        final GetMeasurementResponse result = buildGetMeasurementResponse(measurementsResponseStratix);

        // then
        verifyRealGetMeasurementResponse(result, EXPECTED_BLOCKS_NUM_S10, EXPECTED_RECORD_LEN_S10);
    }

    @Test
    void parse_Agilex() {
        // when
        final GetMeasurementResponse result = buildGetMeasurementResponse(measurementsResponseAgilex);

        // then
        verifyRealGetMeasurementResponse(result, EXPECTED_BLOCKS_NUM_AGILEX, EXPECTED_RECORD_LEN_AGILEX);
    }

    @Test
    void parseAndBuildS10_Success() {
        // given
        byte[] command = prepareGetMeasurementResponseFromFirmware(DEVICE_FAMILY_FUSE_MAP_S10, publicEfuseValuesS10);

        // when
        final GetMeasurementResponse result = buildGetMeasurementResponse(command);

        // then
        verifyGetMeasurementResponseResult(result, DEVICE_FAMILY_FUSE_MAP_S10, publicEfuseValuesS10);
    }

    @Test
    void parseAndBuildFm568_Success() {
        // given
        byte[] command =
            prepareGetMeasurementResponseFromFirmware(DEVICE_FAMILY_FUSE_MAP_FM568, publicEfuseValuesFm568);

        // when
        final GetMeasurementResponse result = buildGetMeasurementResponse(command);

        // then
        verifyGetMeasurementResponseResult(result, DEVICE_FAMILY_FUSE_MAP_FM568, publicEfuseValuesFm568);
    }

    private byte[] prepareGetMeasurementResponseFromFirmware(byte deviceFamilyFuseMap, byte[] publicEfuseValues) {
        final GetMeasurementResponseBuilder builder = new GetMeasurementResponseBuilder();
        builder.setMagic(randAndReturn(magic));
        builder.setSdmSessionId(randAndReturn(sdmSessionId));
        builder.setDeviceUniqueId(randAndReturn(deviceUniqueId));
        builder.setRomVersionNum(randAndReturn(romVersionNum));
        builder.setSdmFwBuildId(randAndReturn(sdmFwBuildId));
        builder.setSdmFwSecurityVersionNum(randAndReturn(sdmFwSecurityVersionNum));
        builder.setDeviceFamilyFuseMap(deviceFamilyFuseMap);
        builder.setReserved(reserved);
        builder.setPublicEfuseValues(randAndReturn(publicEfuseValues));
        builder.setDeviceDhPubKey(randAndReturn(deviceDhPubKey));
        builder.setVerifierDhPubKey(randAndReturn(verifierDhPubKey));
        builder.setCmfDescriptorHash(randAndReturn(cmfDescriptorHash));
        builder.setReserved2(reserved2);
        builder.setNumberOfMeasurementBlocks(numberOfMeasurementBlocks);
        builder.setReserved3(reserved3);
        builder.setMeasurementRecordLen(measurementRecordLen);
        builder.setMeasurementRecord(randAndReturn(measurementRecord));
        builder.setMac(randAndReturn(mac));

        return builder.withActor(EndiannessActor.FIRMWARE).build().array();
    }

    private GetMeasurementResponse buildGetMeasurementResponse(byte[] command) {
        return new GetMeasurementResponseBuilder()
            .withActor(EndiannessActor.FIRMWARE)
            .parse(command)
            .withActor(EndiannessActor.SERVICE)
            .build();
    }

    private void verifyRealGetMeasurementResponse(GetMeasurementResponse result, int expectedBlocksNum,
                                                  int expectedRecordLen) {
        assertEquals(GET_MEASUREMENT_RSP.getCode(), ByteBufferSafe.wrap(result.getMagic()).getInt());
        assertEquals(EXPECTED_SDM_SESSION_ID, ByteBufferSafe.wrap(result.getSdmSessionId()).getInt());
        assertEquals(expectedBlocksNum, result.getNumberOfMeasurementBlocks());
        assertEquals(expectedRecordLen, result.getMeasurementRecordLen());
    }

    private void verifyGetMeasurementResponseResult(GetMeasurementResponse result, byte deviceFamilyFuseMap,
                                                    byte[] publicEfuseValues) {
        assertArrayEquals(magic, result.getMagic());
        assertArrayEquals(sdmSessionId, result.getSdmSessionId());
        assertArrayEquals(romVersionNum, result.getRomVersionNum());
        assertArrayEquals(sdmFwBuildId, result.getSdmFwBuildId());
        assertArrayEquals(sdmFwSecurityVersionNum, result.getSdmFwSecurityVersionNum());
        assertEquals(deviceFamilyFuseMap, result.getDeviceFamilyFuseMap());
        assertArrayEquals(publicEfuseValues, result.getPublicEfuseValues());
        assertArrayEquals(deviceUniqueId, result.getDeviceUniqueId());
        assertArrayEquals(verifierDhPubKey, result.getVerifierDhPubKey());
        assertArrayEquals(cmfDescriptorHash, result.getCmfDescriptorHash());
        assertArrayEquals(reserved2, result.getReserved2());
        assertEquals(numberOfMeasurementBlocks, result.getNumberOfMeasurementBlocks());
        assertEquals(reserved3, result.getReserved3());
        assertEquals(measurementRecordLen, result.getMeasurementRecordLen());
        assertArrayEquals(measurementRecord, result.getMeasurementRecord());
        assertArrayEquals(mac, result.getMac());
    }

    private byte[] randAndReturn(byte[] arr) {
        random.nextBytes(arr);
        return Arrays.copyOf(arr, arr.length);
    }
}

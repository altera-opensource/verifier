/*
 * This project is licensed as below.
 *
 * **************************************************************************
 *
 * Copyright 2020-2021 Intel Corporation. All Rights Reserved.
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

import com.intel.bkp.ext.core.endianess.EndianessActor;
import com.intel.bkp.ext.utils.ByteBufferSafe;
import com.intel.bkp.verifier.Utils;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.junit.jupiter.MockitoExtension;

import java.util.Arrays;
import java.util.Random;

import static com.intel.bkp.verifier.command.Magic.GET_MEASUREMENT_RSP;

@ExtendWith(MockitoExtension.class)
class GetMeasurementResponseBuilderTest {

    private static final String TEST_FOLDER = "responses/";
    private static final String FILENAME_STRATIX_RESPONSE = "measurements_response_stratix10.bin";
    private static final String FILENAME_AGILEX_RESPONSE = "measurements_response_agilex.bin";

    private static final int EXPECTED_SDM_SESSION_ID = 1;
    private static final int EXPECTED_BLOCKS_NUM_S10 = 4;
    private static final int EXPECTED_RECORD_LEN_S10 = 184;
    private static final int EXPECTED_BLOCKS_NUM_AGILEX = 5;
    private static final int EXPECTED_RECORD_LEN_AGILEX = 240;

    private static byte[] measurementsResponseStratix;
    private static byte[] measurementsResponseAgilex;

    private final Random random = new Random();

    @InjectMocks
    private GetMeasurementResponseBuilder sut;

    @BeforeAll
    static void init() throws Exception {
        measurementsResponseStratix = Utils.readFromResources(TEST_FOLDER, FILENAME_STRATIX_RESPONSE);
        measurementsResponseAgilex = Utils.readFromResources(TEST_FOLDER, FILENAME_AGILEX_RESPONSE);
    }

    @Test
    void parse_S10() {
        // when
        final GetMeasurementResponse result = sut
            .withActor(EndianessActor.FIRMWARE)
            .parse(measurementsResponseStratix)
            .withActor(EndianessActor.SERVICE)
            .build();

        // then
        Assertions.assertEquals(GET_MEASUREMENT_RSP.getCode(),
            ByteBufferSafe.wrap(result.getMagic()).getInt());
        Assertions.assertEquals(EXPECTED_SDM_SESSION_ID, ByteBufferSafe.wrap(result.getSdmSessionId()).getInt());
        Assertions.assertEquals(EXPECTED_BLOCKS_NUM_S10, result.getNumberOfMeasurementBlocks());
        Assertions.assertEquals(EXPECTED_RECORD_LEN_S10, result.getMeasurementRecordLen());
    }

    @Test
    void parse_Agilex() {
        // when
        final GetMeasurementResponse result = sut
            .withActor(EndianessActor.FIRMWARE)
            .parse(measurementsResponseAgilex)
            .withActor(EndianessActor.SERVICE)
            .build();

        // then
        Assertions.assertEquals(GET_MEASUREMENT_RSP.getCode(),
            ByteBufferSafe.wrap(result.getMagic()).getInt());
        Assertions.assertEquals(EXPECTED_SDM_SESSION_ID, ByteBufferSafe.wrap(result.getSdmSessionId()).getInt());
        Assertions.assertEquals(EXPECTED_BLOCKS_NUM_AGILEX, result.getNumberOfMeasurementBlocks());
        Assertions.assertEquals(EXPECTED_RECORD_LEN_AGILEX, result.getMeasurementRecordLen());
    }

    @Test
    void build_parse() {
        // given
        final byte[] magic = new byte[Integer.BYTES];
        final byte[] sdmSessionId = new byte[Integer.BYTES];
        final byte[] deviceUniqueId = new byte[Long.BYTES];
        final byte[] romVersionNum = new byte[Integer.BYTES];
        final byte[] sdmFwBuildId = new byte[GetMeasurementResponseBuilder.SDM_FW_BUILD_ID_LEN];
        final byte[] sdmFwSecurityVersionNum = new byte[Integer.BYTES];
        final byte[] publicEfuseValues = new byte[GetMeasurementResponseBuilder.PUB_EFUSE_VALUES_LEN];
        final byte[] deviceDhPubKey = new byte[GetMeasurementResponseBuilder.DH_PUB_KEY_LEN];
        final byte[] verifierDhPubKey = new byte[GetMeasurementResponseBuilder.DH_PUB_KEY_LEN];
        final byte[] cmfDescriptorHash = new byte[GetMeasurementResponseBuilder.CMF_DESCRIPTOR_HASH_LEN];
        final byte numberOfMeasurementBlocks = 2;
        final short measurementRecordLen = 100;
        final byte[] measurementRecord = new byte[measurementRecordLen];
        final byte[] mac = new byte[GetMeasurementResponseBuilder.SHA_384_MAC_LEN];

        sut.setMagic(randAndReturn(magic));
        sut.setSdmSessionId(randAndReturn(sdmSessionId));
        sut.setDeviceUniqueId(randAndReturn(deviceUniqueId));
        sut.setRomVersionNum(randAndReturn(romVersionNum));
        sut.setSdmFwBuildId(randAndReturn(sdmFwBuildId));
        sut.setSdmFwSecurityVersionNum(randAndReturn(sdmFwSecurityVersionNum));
        sut.setPublicEfuseValues(randAndReturn(publicEfuseValues));
        sut.setDeviceDhPubKey(randAndReturn(deviceDhPubKey));
        sut.setVerifierDhPubKey(randAndReturn(verifierDhPubKey));
        sut.setCmfDescriptorHash(randAndReturn(cmfDescriptorHash));
        sut.setNumberOfMeasurementBlocks(numberOfMeasurementBlocks);
        sut.setMeasurementRecordLen(measurementRecordLen);
        sut.setMeasurementRecord(randAndReturn(measurementRecord));
        sut.setMac(randAndReturn(mac));

        // when
        final byte[] result = sut.withActor(EndianessActor.FIRMWARE)
            .build()
            .array();

        final GetMeasurementResponseBuilder parsed = sut.withActor(EndianessActor.FIRMWARE)
            .parse(result);

        // then
        Assertions.assertArrayEquals(sdmSessionId, parsed.getSdmSessionId());
        Assertions.assertArrayEquals(romVersionNum, parsed.getRomVersionNum());
        Assertions.assertArrayEquals(sdmFwBuildId, parsed.getSdmFwBuildId());
        Assertions.assertArrayEquals(sdmFwSecurityVersionNum, parsed.getSdmFwSecurityVersionNum());
        Assertions.assertArrayEquals(publicEfuseValues, parsed.getPublicEfuseValues());
        Assertions.assertArrayEquals(deviceUniqueId, parsed.getDeviceUniqueId());
        Assertions.assertArrayEquals(verifierDhPubKey, parsed.getVerifierDhPubKey());
        Assertions.assertArrayEquals(cmfDescriptorHash, parsed.getCmfDescriptorHash());
        Assertions.assertEquals(numberOfMeasurementBlocks, parsed.getNumberOfMeasurementBlocks());
        Assertions.assertEquals(measurementRecordLen, parsed.getMeasurementRecordLen());
        Assertions.assertArrayEquals(measurementRecord, parsed.getMeasurementRecord());
        Assertions.assertArrayEquals(mac, parsed.getMac());
    }

    private byte[] randAndReturn(byte[] arr) {
        random.nextBytes(arr);
        return Arrays.copyOf(arr, arr.length);
    }
}

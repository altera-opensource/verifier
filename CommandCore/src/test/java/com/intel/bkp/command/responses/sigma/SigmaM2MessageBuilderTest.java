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
import com.intel.bkp.core.exceptions.ParseStructureException;
import com.intel.bkp.core.psgcertificate.PsgSignatureBuilder;
import com.intel.bkp.core.psgcertificate.model.PsgSignatureCurveType;
import com.intel.bkp.utils.exceptions.ByteBufferSafeException;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.util.Random;

import static com.intel.bkp.command.responses.sigma.DeviceFamilyFuseMap.FM568;
import static com.intel.bkp.command.responses.sigma.DeviceFamilyFuseMap.S10;
import static com.intel.bkp.test.AssertionUtils.assertThatArrayIsSubarrayOfAnotherArray;
import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

public class SigmaM2MessageBuilderTest {

    private static final byte DEVICE_FAMILY_FUSE_MAP_S10 = S10.getByteFromOrdinal();
    private static final byte DEVICE_FAMILY_FUSE_MAP_FM568 = FM568.getByteFromOrdinal();

    private final byte[] magic = new byte[Integer.BYTES];
    private final byte[] sdmSessionId = new byte[Integer.BYTES];
    private final byte[] deviceUniqueId = new byte[Long.BYTES];
    private final byte[] romVersionNum = new byte[Integer.BYTES];
    private final byte[] sdmFwBuildId = new byte[SigmaM2MessageBuilder.SDM_FW_BUILD_ID_LEN];
    private final byte[] sdmFwSecurityVersionNum = new byte[Integer.BYTES];
    private final byte[] reserved = new byte[SigmaM2MessageBuilder.RESERVED_LEN];
    private final byte[] publicEfuseValuesS10 = new byte[S10.getEfuseValuesFieldLen()];
    private final byte[] publicEfuseValuesFm568 = new byte[FM568.getEfuseValuesFieldLen()];
    private final byte[] deviceDhPubKey = new byte[SigmaM2MessageBuilder.DH_PUB_KEY_LEN];
    private final byte[] bkpsDhPubKey = new byte[SigmaM2MessageBuilder.DH_PUB_KEY_LEN];
    private final byte[] mac = new byte[SigmaM2MessageBuilder.SHA_384_MAC_LEN];

    @BeforeEach
    public void setUp() {
        Random random = new Random();
        random.nextBytes(magic);
        random.nextBytes(sdmSessionId);
        random.nextBytes(deviceUniqueId);
        random.nextBytes(romVersionNum);
        random.nextBytes(sdmFwBuildId);
        random.nextBytes(sdmFwSecurityVersionNum);
        random.nextBytes(publicEfuseValuesS10);
        random.nextBytes(publicEfuseValuesFm568);
        random.nextBytes(deviceDhPubKey);
        random.nextBytes(bkpsDhPubKey);
        random.nextBytes(mac);
    }

    @Test
    public void parseAndBuildS10_Success() {
        // given
        byte[] command = prepareSigmaM2FromFirmware(DEVICE_FAMILY_FUSE_MAP_S10, publicEfuseValuesS10);

        // when
        SigmaM2Message result = buildM2Message(command);

        // then
        verifyM2Result(result, DEVICE_FAMILY_FUSE_MAP_S10, publicEfuseValuesS10);
    }

    @Test
    public void parseAndBuildFm568_Success() {
        // given
        byte[] command = prepareSigmaM2FromFirmware(DEVICE_FAMILY_FUSE_MAP_FM568, publicEfuseValuesFm568);

        // when
        SigmaM2Message result = buildM2Message(command);

        // then
        verifyM2Result(result, DEVICE_FAMILY_FUSE_MAP_FM568, publicEfuseValuesFm568);
    }

    @Test
    public void parse_FromArrayS10_Success() {
        // given
        byte[] command = prepareSigmaM2FromFirmware(DEVICE_FAMILY_FUSE_MAP_S10, publicEfuseValuesS10);
        SigmaM2Message sigmaM2Message = buildM2Message(command);

        // when
        SigmaM2Message result = new SigmaM2MessageBuilder().parse(sigmaM2Message.array()).build();

        // then
        verifyM2Result(result, DEVICE_FAMILY_FUSE_MAP_S10, publicEfuseValuesS10);
    }

    @Test
    public void parse_FromArrayFm568_Success() {
        // given
        byte[] command = prepareSigmaM2FromFirmware(DEVICE_FAMILY_FUSE_MAP_FM568, publicEfuseValuesFm568);
        SigmaM2Message sigmaM2Message = buildM2Message(command);

        // when
        SigmaM2Message result = new SigmaM2MessageBuilder().parse(sigmaM2Message.array()).build();

        // then
        verifyM2Result(result, DEVICE_FAMILY_FUSE_MAP_FM568, publicEfuseValuesFm568);
    }

    @Test
    public void parse_NotEnoughData_Throws() {
        // given
        byte[] command = new byte[10];

        // when-then
        assertThrows(ByteBufferSafeException.class, () -> new SigmaM2MessageBuilder().parse(command));
    }

    @Test
    public void getDataForSignatureS10_Success() {
        // given
        byte[] command = prepareSigmaM2FromFirmware(DEVICE_FAMILY_FUSE_MAP_S10, publicEfuseValuesS10);

        // when
        byte[] result = buildDataForSignature(command);

        // then
        assertThatArrayIsSubarrayOfAnotherArray(command, result);
    }

    @Test
    public void getDataForSignatureFm568_Success() {
        // given
        byte[] command = prepareSigmaM2FromFirmware(DEVICE_FAMILY_FUSE_MAP_FM568, publicEfuseValuesFm568);

        // when
        byte[] result = buildDataForSignature(command);

        // then
        assertThatArrayIsSubarrayOfAnotherArray(command, result);
    }

    @Test
    public void getDataAndSignatureForMacS10_Success() {
        // given
        byte[] command = prepareSigmaM2FromFirmware(DEVICE_FAMILY_FUSE_MAP_S10, publicEfuseValuesS10);

        // when
        byte[] result = buildDataForMac(command);

        // then
        assertThatArrayIsSubarrayOfAnotherArray(command, result);
    }

    @Test
    public void getDataAndSignatureForMacFm568_Success() {
        // given
        byte[] command = prepareSigmaM2FromFirmware(DEVICE_FAMILY_FUSE_MAP_FM568, publicEfuseValuesFm568);

        // when
        byte[] result = buildDataForMac(command);

        // then
        assertThatArrayIsSubarrayOfAnotherArray(command, result);
    }

    @Test
    public void parseAndBuild_InvalidSignature_Throws() {
        // given
        byte[] command = new byte[1000];

        // when-then
        assertThrows(ParseStructureException.class,
            () -> new SigmaM2MessageBuilder().parse(command).build());
    }

    @Test
    public void parseAndBuild_TooSmallData_Throws() {
        // given
        byte[] command = new byte[1];

        // when-then
        assertThrows(ByteBufferSafeException.class,
            () -> new SigmaM2MessageBuilder().parse(command).build());
    }

    private byte[] prepareSigmaM2FromFirmware(byte deviceFamilyFuseMap, byte[] publicEfuseValues) {
        final SigmaM2MessageBuilder builder = new SigmaM2MessageBuilder();
        builder.setMagic(magic);
        builder.setSdmSessionId(sdmSessionId);
        builder.setDeviceUniqueId(deviceUniqueId);
        builder.setRomVersionNum(romVersionNum);
        builder.setSdmFwBuildId(sdmFwBuildId);
        builder.setSdmFwSecurityVersionNum(sdmFwSecurityVersionNum);
        builder.setDeviceFamilyFuseMap(deviceFamilyFuseMap);
        builder.setReserved(reserved);
        builder.setPublicEfuseValues(publicEfuseValues);
        builder.setDeviceDhPubKey(deviceDhPubKey);
        builder.setBkpsDhPubKey(bkpsDhPubKey);
        builder.setSignatureBuilder(PsgSignatureBuilder.empty(PsgSignatureCurveType.SECP384R1));
        builder.setMac(mac);

        return builder.withActor(EndiannessActor.FIRMWARE).build().array();
    }

    private SigmaM2Message buildM2Message(byte[] command) {
        return new SigmaM2MessageBuilder()
            .withActor(EndiannessActor.FIRMWARE)
            .parse(command)
            .withActor(EndiannessActor.SERVICE)
            .build();
    }

    private byte[] buildDataForSignature(byte[] command) {
        return new SigmaM2MessageBuilder()
            .withActor(EndiannessActor.FIRMWARE)
            .parse(command)
            .getDataForSignature();
    }

    private byte[] buildDataForMac(byte[] command) {
        return new SigmaM2MessageBuilder()
            .withActor(EndiannessActor.FIRMWARE)
            .parse(command)
            .getDataAndSignatureForMac();
    }

    private void verifyM2Result(SigmaM2Message result, byte deviceFamilyFuseMap, byte[] publicEfuseValues) {
        assertArrayEquals(magic, result.getMagic());
        assertArrayEquals(sdmSessionId, result.getSdmSessionId());
        assertArrayEquals(deviceUniqueId, result.getDeviceUniqueId());
        assertArrayEquals(romVersionNum, result.getRomVersionNum());
        assertArrayEquals(sdmFwBuildId, result.getSdmFwBuildId());
        assertArrayEquals(sdmFwSecurityVersionNum, result.getSdmFwSecurityVersionNum());
        assertEquals(deviceFamilyFuseMap, result.getDeviceFamilyFuseMap());
        assertArrayEquals(reserved, result.getReserved());
        assertArrayEquals(publicEfuseValues, result.getPublicEfuseValues());
        assertArrayEquals(deviceDhPubKey, result.getDeviceDhPubKey());
        assertArrayEquals(bkpsDhPubKey, result.getBkpsDhPubKey());
        Assertions.assertArrayEquals(PsgSignatureBuilder.empty(PsgSignatureCurveType.SECP384R1).build().array(),
            result.getSignature());
        assertArrayEquals(mac, result.getMac());
    }
}


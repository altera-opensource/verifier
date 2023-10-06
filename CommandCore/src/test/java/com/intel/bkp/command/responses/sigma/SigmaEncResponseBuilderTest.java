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
import com.intel.bkp.utils.ByteSwap;
import com.intel.bkp.utils.exceptions.ByteBufferSafeException;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.util.concurrent.ThreadLocalRandom;

import static com.intel.bkp.test.AssertionUtils.assertThatArrayIsSubarrayOfAnotherArray;
import static com.intel.bkp.utils.ByteSwapOrder.B2L;
import static com.intel.bkp.utils.ByteSwapOrder.CONVERT;
import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

public class SigmaEncResponseBuilderTest {

    private final byte[] sdmSessionId = new byte[SigmaEncResponseBuilder.SDM_SESSION_ID_LEN];
    private final byte[] payload = new byte[8];
    private final int payloadLen = payload.length;
    private final byte[] mac = new byte[SigmaEncResponseBuilder.MAC_LEN];

    @BeforeEach
    public void setUp() {
        final var random = ThreadLocalRandom.current();
        random.nextBytes(sdmSessionId);
        random.nextBytes(payload);
        random.nextBytes(mac);
    }

    @Test
    public void parseAndBuild_WithCorrectMac_Success() {
        // given
        byte[] mac = prepareCorrectMac();
        byte[] command = prepareSigmaEncResponseWithMac(mac);

        // when
        SigmaEncResponse result = new SigmaEncResponseBuilder()
            .withActor(EndiannessActor.FIRMWARE)
            .parse(command)
            .withActor(EndiannessActor.SERVICE)
            .build();

        // then
        assertArrayEquals(sdmSessionId, result.getSdmSessionId());
        assertArrayEquals(payload, result.getEncryptedPayload());
        assertEquals(payloadLen, result.getPayloadLen());
        assertArrayEquals(payload, result.getEncryptedPayload());
        assertArrayEquals(mac, result.getMac());
    }

    @Test
    public void parse_WithArray_Success() {
        // given
        byte[] mac = prepareCorrectMac();
        byte[] command = prepareSigmaEncResponseWithMac(mac);
        SigmaEncResponse sigmaEncResponse = new SigmaEncResponseBuilder()
            .withActor(EndiannessActor.FIRMWARE)
            .parse(command)
            .build();

        // when
        SigmaEncResponse result = new SigmaEncResponseBuilder()
            .withActor(EndiannessActor.FIRMWARE)
            .parse(sigmaEncResponse.array())
            .withActor(EndiannessActor.SERVICE)
            .build();

        // then
        assertArrayEquals(sdmSessionId, result.getSdmSessionId());
        assertEquals(payloadLen, result.getPayloadLen());
        assertArrayEquals(payload, result.getEncryptedPayload());
        assertArrayEquals(payload, result.getEncryptedPayload());
        assertArrayEquals(mac, result.getMac());
    }

    @Test
    public void parse_WithArray_HeaderOnly_Success() {
        // given
        byte[] command = prepareSigmaEncHeaderOnly().build().array();
        SigmaEncResponse sigmaEncResponse = new SigmaEncResponseBuilder()
            .withActor(EndiannessActor.FIRMWARE)
            .parse(command)
            .build();

        // when
        SigmaEncResponse result = new SigmaEncResponseBuilder()
            .withActor(EndiannessActor.FIRMWARE)
            .parse(sigmaEncResponse.array())
            .withActor(EndiannessActor.SERVICE)
            .build();

        // then
        assertEquals(command.length, result.array().length);
    }

    @Test
    public void getDataToMac_Success() {
        // given
        byte[] mac = prepareCorrectMac();
        byte[] command = prepareSigmaEncResponseWithMac(mac);

        // when
        byte[] result = new SigmaEncResponseBuilder()
            .withActor(EndiannessActor.FIRMWARE)
            .parse(command)
            .getDataToMac();

        // then
        assertThatArrayIsSubarrayOfAnotherArray(command, result);
    }

    @Test
    public void getDataToDecrypt_Success() {
        // given
        byte[] mac = prepareCorrectMac();
        byte[] command = prepareSigmaEncResponseWithMac(mac);

        // when
        byte[] result = new SigmaEncResponseBuilder()
            .withActor(EndiannessActor.FIRMWARE)
            .parse(command)
            .getDataToDecrypt();

        // then
        assertThatArrayIsSubarrayOfAnotherArray(command, result);
    }

    @Test
    public void parseAndBuild_WithIncorrectMac_Success() {
        // given
        byte[] mac = prepareIncorrectMac();
        // when
        assertThrows(ByteBufferSafeException.class, () -> {
            byte[] command = prepareSigmaEncResponseWithMac(mac);
        });
    }

    @Test
    public void parseAndBuild_TooBigData_Throws() {
        // given
        byte[] command = new byte[1000];

        // when

        assertThrows(ByteBufferSafeException.class, () -> new SigmaEncResponseBuilder().parse(command).build());
    }

    @Test
    public void parseAndBuild_TooSmallData_Throws() {
        // given
        byte[] command = new byte[1];

        // when
        assertThrows(ByteBufferSafeException.class, () -> new SigmaEncResponseBuilder().parse(command).build());
    }


    private byte[] prepareSigmaEncResponseWithMac(byte[] mac) {
        SigmaEncResponseBuilder builder = prepareSigmaEncNoMac();
        builder.setMac(mac);
        return builder.build().array();
    }

    private SigmaEncResponseBuilder prepareSigmaEncHeaderOnly() {
        SigmaEncResponseBuilder builder = new SigmaEncResponseBuilder();
        builder.setFlowType(SigmaEncFlowType.HEADER_ONLY);
        return builder;
    }

    private SigmaEncResponseBuilder prepareSigmaEncNoMac() {
        SigmaEncResponseBuilder builder = new SigmaEncResponseBuilder();
        builder.setFlowType(SigmaEncFlowType.WITH_ENCRYPTED_RESPONSE);
        builder.setSdmSessionId(swapBigToLittleByInt(sdmSessionId));
        builder.setPayloadLen(ByteSwap.getSwappedInt(payloadLen, CONVERT));
        builder.setEncryptedPayload(payload);
        return builder;
    }

    private byte[] swapBigToLittleByInt(byte[] array) {
        return ByteSwap.getSwappedArrayByInt(array, B2L);
    }

    private byte[] prepareCorrectMac() {
        return mac;
    }

    private byte[] prepareIncorrectMac() {
        return new byte[]{3};
    }

}

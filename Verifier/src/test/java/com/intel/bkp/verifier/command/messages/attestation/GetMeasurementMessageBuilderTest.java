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

package com.intel.bkp.verifier.command.messages.attestation;

import com.intel.bkp.utils.ByteBufferSafe;
import com.intel.bkp.verifier.Utils;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.junit.jupiter.MockitoExtension;

import java.nio.ByteOrder;

import static com.intel.bkp.utils.HexConverter.toHex;
import static com.intel.bkp.verifier.command.Magic.GET_MEASUREMENT;

@ExtendWith(MockitoExtension.class)
class GetMeasurementMessageBuilderTest {

    private static final String TEST_FOLDER = "messages/";
    private static final String MEASUREMENTS_CMD_FILENAME = "measurements_cmd.bin";
    private static final String VERIFIER_DH_PUBKEY =
        "E556DCF69048124658D9B40AC13E70074CBB245135DF7851F0FAEE0C8CD43CAFBBD5DDD042ED40C630A2BC37CB03EB2" +
            "D1F01DC9DC33CD20FADD8F150B825981B391F100670404C63E7857D10625083E7A06C343B66A17A4BF9A0CD52A855A4B6";
    private static final String CONTEXT = "abcdefg";

    private static byte[] measurementsCmd;

    @InjectMocks
    private GetMeasurementMessageBuilder sut;

    @BeforeAll
    static void init() throws Exception {
        measurementsCmd = Utils.readFromResources(TEST_FOLDER, MEASUREMENTS_CMD_FILENAME);
    }

    @Test
    void parse() {
        // when
        final GetMeasurementMessage result = sut
            .parse(measurementsCmd)
            .build();

        // then
        Assertions.assertEquals(GET_MEASUREMENT.getCode(),
            ByteBufferSafe.wrap(result.getMagic()).getInt(ByteOrder.LITTLE_ENDIAN));
        Assertions.assertEquals(VERIFIER_DH_PUBKEY, toHex(result.getVerifierDhPubKey()));
        Assertions.assertTrue(new String(result.getVerifierInputContext()).contains(CONTEXT));
    }
}

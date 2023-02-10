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

package com.intel.bkp.verifier.command.responses.subkey;

import com.intel.bkp.core.endianness.EndiannessActor;
import com.intel.bkp.utils.ByteBufferSafe;
import com.intel.bkp.verifier.Utils;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.junit.jupiter.MockitoExtension;

import static com.intel.bkp.verifier.command.Magic.CREATE_SUBKEY_RSP;

@ExtendWith(MockitoExtension.class)
class CreateAttestationSubKeyResponseBuilderTest {

    private static final String TEST_FOLDER = "responses/";
    private static final String SUBKEY_RESPONSE_FILENAME = "subkey_response.bin";

    private static byte[] subkeyResponse;

    @InjectMocks
    private CreateAttestationSubKeyResponseBuilder sut;

    @BeforeAll
    static void init() throws Exception {
        subkeyResponse = Utils.readFromResources(TEST_FOLDER, SUBKEY_RESPONSE_FILENAME);
    }

    @Test
    void parse() {
        // when
        final CreateAttestationSubKeyResponse result = sut
            .withActor(EndiannessActor.FIRMWARE)
            .parse(subkeyResponse)
            .withActor(EndiannessActor.SERVICE)
            .build();

        // then
        Assertions.assertEquals(CREATE_SUBKEY_RSP.getCode(),
            ByteBufferSafe.wrap(result.getMagic()).getInt());
    }
}

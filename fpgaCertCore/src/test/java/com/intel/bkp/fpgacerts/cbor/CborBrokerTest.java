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

package com.intel.bkp.fpgacerts.cbor;

import com.intel.bkp.test.FileUtils;
import com.intel.bkp.test.rim.OneKeyGenerator;
import com.intel.bkp.test.rim.RimGenerator;
import com.upokecenter.cbor.CBORObject;
import lombok.SneakyThrows;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.junit.jupiter.MockitoExtension;

import static com.intel.bkp.fpgacerts.cbor.signer.cose.model.AlgorithmId.ECDSA_384;
import static com.intel.bkp.test.FileUtils.TEST_FOLDER;
import static org.junit.jupiter.api.Assertions.assertEquals;

@ExtendWith(MockitoExtension.class)
class CborBrokerTest {

    private static CBORObject cbor;

    @SneakyThrows
    private static void generateSignedRim() {
        final var signingKey = OneKeyGenerator.generate(ECDSA_384);
        final byte[] signed = RimGenerator.instance()
                .privateKey(signingKey.getPrivateKey())
                .publicKey(signingKey.getPublicKey())
                .generate();
        cbor = CborObjectParser.instance().parse(signed);
    }

    @SneakyThrows
    private static void generateUnsignedRim() {
        final var signingKey = OneKeyGenerator.generate(ECDSA_384);
        final byte[] signed = RimGenerator.instance()
                .signed(false)
                .publicKey(signingKey.getPublicKey())
                .generate();
        cbor = CborObjectParser.instance().parse(signed);
    }

    @Test
    void detectCborType_SignedRim_Success() {
        // given
        generateSignedRim();

        // when
        CborConverter actual = CborBroker.detectCborType(cbor);

        // then
        assertEquals(CborConverter.RIM_SIGNED, actual);
    }

    @Test
    void detectCborType_UnsignedRim_Success() {
        // given
        generateUnsignedRim();

        // when
        CborConverter actual = CborBroker.detectCborType(cbor);

        // then
        assertEquals(CborConverter.RIM_UNSIGNED, actual);
    }

    @Test
    @SneakyThrows
    void detectCborType_SignedXrim_Success() {
        // given
        byte[] cborData = FileUtils.readFromResources(TEST_FOLDER, "fw_xrim_signed.xrim");

        // when
        CborConverter actual = CborBroker.detectCborType(parse(cborData));

        // then
        assertEquals(CborConverter.XRIM_SIGNED, actual);
    }

    @Test
    @SneakyThrows
    void detectCborType_UnsignedXrim_Success() {
        // given
        byte[] cborData = FileUtils.readFromResources(TEST_FOLDER, "fw_xrim_unsigned.xrim");

        // when
        CborConverter actual = CborBroker.detectCborType(parse(cborData));

        // then
        assertEquals(CborConverter.XRIM_UNSIGNED, actual);
    }

    private CBORObject parse(byte[] cborData) {
        return CborObjectParser.instance().parse(cborData);
    }

}

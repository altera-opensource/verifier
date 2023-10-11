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

package com.intel.bkp.fpgacerts.cbor.signer;

import com.intel.bkp.fpgacerts.cbor.rim.RimSigned;
import com.intel.bkp.fpgacerts.cbor.rim.builder.RimUnsignedBuilder;
import com.intel.bkp.fpgacerts.cbor.rim.parser.RimSignedParser;
import com.intel.bkp.fpgacerts.cbor.signer.cose.CborKeyPair;
import com.intel.bkp.fpgacerts.cbor.signer.cose.model.AlgorithmId;
import com.intel.bkp.test.FileUtils;
import com.intel.bkp.test.rim.OneKeyGenerator;
import org.junit.jupiter.api.Test;

import static com.intel.bkp.test.FileUtils.TEST_FOLDER;
import static org.junit.jupiter.api.Assertions.assertTrue;


class CoseMessageSignerTest {

    private final CoseMessageSigner sut = CoseMessageSigner.instance();

    @Test
    void sign_WithGeneratedKey_Success() throws Exception {
        final CborKeyPair signingKey = OneKeyGenerator.generate(AlgorithmId.ECDSA_384);
        final byte[] rawSignedData = loadDesignRimData();
        final RimSigned rimSigned = RimSignedParser.instance().parse(rawSignedData);
        final byte[] payload = RimUnsignedBuilder.instance().build(rimSigned.getPayload());
        final var rimProtected = rimSigned.getProtectedData();

        // when
        final byte[] signed = sut.sign(signingKey, payload, rimProtected);
        final boolean valid = sut.verify(signingKey, signed);

        // then
        assertTrue(valid);
    }

    private static byte[] loadDesignRimData() throws Exception {
        return FileUtils.readFromResources(TEST_FOLDER, "fw_rim_signed.rim");
    }
}

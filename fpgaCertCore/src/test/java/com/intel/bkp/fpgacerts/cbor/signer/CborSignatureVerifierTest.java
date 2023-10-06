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

import com.intel.bkp.fpgacerts.cbor.signer.cose.CborKeyPair;
import com.intel.bkp.test.EcKeyLoader;
import com.intel.bkp.test.FileUtils;
import com.intel.bkp.test.KeyGenUtils;
import com.intel.bkp.test.rim.XrimGenerator;
import org.junit.jupiter.api.Test;

import java.io.ByteArrayInputStream;
import java.security.KeyPair;
import java.security.PublicKey;

import static com.intel.bkp.test.FileUtils.TEST_FOLDER;
import static org.junit.jupiter.api.Assertions.assertTrue;

class CborSignatureVerifierTest {

    private final CborSignatureVerifier sut = new CborSignatureVerifier();

    @Test
    void verify_WithFwRimSample_WithCorrectSignature_ReturnsTrue() throws Exception {
        // given
        byte[] pubKeyPem = FileUtils.readFromResources(TEST_FOLDER, "fw_signed_rim_signing_public.pem");
        final PublicKey publicKey = EcKeyLoader.getPublicKey(new ByteArrayInputStream(pubKeyPem));
        byte[] cborData = FileUtils.readFromResources(TEST_FOLDER, "fw_rim_signed.rim");

        // when
        final boolean valid = sut.verify(publicKey, cborData);

        // then
        assertTrue(valid);
    }

    @Test
    void verify_WithDesignRimSample_Success() throws Exception {
        // given
        final CborKeyPair signingKey = prepareOneKey();
        final byte[] signed = FileUtils.readFromResources(TEST_FOLDER, "design_rim_signed.rim");

        // when
        final boolean verified = sut.verify(signingKey.getPublicKey(), signed);

        // then
        assertTrue(verified);
    }

    @Test
    void verify_WithGeneratedXCoRim_Success() {
        // given
        final KeyPair keyPair = KeyGenUtils.genEc384();
        final byte[] signed = XrimGenerator.instance().keyPair(keyPair).generate();
        final PublicKey pubKey = keyPair.getPublic();

        // when
        final boolean verified = sut.verify(pubKey, signed);

        // then
        assertTrue(verified);
    }

    private static CborKeyPair prepareOneKey() throws Exception {
        byte[] pubKeyPem = FileUtils.readFromResources(TEST_FOLDER, "design_signed_rim_signing_public.pem");
        final PublicKey publicKey = EcKeyLoader.getPublicKey(new ByteArrayInputStream(pubKeyPem));
        return CborKeyPair.fromKeyPair(publicKey, null);
    }
}

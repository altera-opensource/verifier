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

package com.intel.bkp.fpgacerts.cbor.utils;

import com.intel.bkp.fpgacerts.cbor.exception.RimVerificationException;
import com.intel.bkp.fpgacerts.cbor.rim.RimProtectedHeader;
import com.intel.bkp.fpgacerts.cbor.rim.RimSigned;
import com.intel.bkp.fpgacerts.cbor.rim.parser.RimSignedParser;
import com.intel.bkp.fpgacerts.cbor.signer.cose.CborKeyPair;
import com.intel.bkp.fpgacerts.cbor.signer.cose.exception.CoseException;
import com.intel.bkp.test.rim.OneKeyGenerator;
import com.intel.bkp.test.rim.RimGenerator;
import org.junit.jupiter.api.Test;

import static com.intel.bkp.fpgacerts.cbor.signer.cose.model.AlgorithmId.ECDSA_384;
import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class SignatureTimeValidatorTest {

    @Test
    void verify_WithValidSignatureTime_Success() throws Exception {
        // given
        final RimSigned data = generateSignedRim(false);

        // when-then
        assertDoesNotThrow(() -> SignatureTimeValidator.verify(data));
    }

    @Test
    void verify_WithMissingProtectedData_ThrowsException() {
        // given
        final RimSigned data = RimSigned.builder().protectedData(RimProtectedHeader.builder().build()).build();

        // when-then
        final var ex = assertThrows(RimVerificationException.class,
            () -> SignatureTimeValidator.verify(data));

        // then
        assertEquals("CoRIM verification failed: signature validity is not set.", ex.getMessage());
    }

    @Test
    void verify_WithExpiredSignatureTime_ThrowsException() throws Exception {
        // given
        final RimSigned data = generateSignedRim(true);

        // when-then
        final var ex = assertThrows(RimVerificationException.class,
            () -> SignatureTimeValidator.verify(data));

        // then
        assertTrue(ex.getMessage().contains("CoRIM verification failed: signature expired at:"));
    }

    private static RimSigned generateSignedRim(boolean expired) throws CoseException {
        final CborKeyPair pair = OneKeyGenerator.generate(ECDSA_384);
        final byte[] signed = RimGenerator
            .instance()
            .privateKey(pair.getPrivateKey())
            .publicKey(pair.getPublicKey())
            .expired(expired)
            .generate();
        return RimSignedParser.instance().parse(signed);
    }
}

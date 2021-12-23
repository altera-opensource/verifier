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

package com.intel.bkp.verifier.sigma;

import com.intel.bkp.ext.core.psgcertificate.exceptions.PsgInvalidSignatureException;
import com.intel.bkp.ext.crypto.ecdh.EcdhKeyPair;
import com.intel.bkp.ext.crypto.exceptions.EcdhKeyPairException;
import com.intel.bkp.verifier.command.responses.attestation.GetMeasurementResponse;
import com.intel.bkp.verifier.database.model.S10CacheEntity;
import com.intel.bkp.verifier.exceptions.SigmaException;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import static com.intel.bkp.ext.utils.HexConverter.toHex;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class GetMeasurementVerifierTest {

    private static final byte[] VERIFIER_DH = new byte[96];

    private static EcdhKeyPair serviceDhKeyPair;

    @Mock
    private GetMeasurementResponse response;

    @Mock
    private S10CacheEntity entity;

    @Mock
    private GetMeasurementPakSubKeySignatureVerifier pakSignatureVerifier;

    @Mock
    private SigmaM2VerifierDhPubKeyVerifier dhPubKeyVerifier;

    @InjectMocks
    private GetMeasurementVerifier sut;

    @BeforeAll
    static void setUp() throws EcdhKeyPairException {
        serviceDhKeyPair = EcdhKeyPair.generate();
    }

    @Test
    void verify_IntegrityAndSignatureVerificationCalled() throws Exception {
        // given
        mockAlias();
        when(response.getVerifierDhPubKey()).thenReturn(VERIFIER_DH);

        // when
        sut.verify(response, serviceDhKeyPair, entity);

        // then
        verify(pakSignatureVerifier).verify(any(), eq(response));
        verify(dhPubKeyVerifier).verify(serviceDhKeyPair.getPublicKey(), VERIFIER_DH);
    }

    @Test
    void verify_SignatureFailed_Throws() throws Exception {
        // given
        mockAlias();
        doThrow(new PsgInvalidSignatureException("test")).when(pakSignatureVerifier).verify(any(), eq(response));

        // when-then
        Assertions.assertThrows(SigmaException.class, () -> sut.verify(response, serviceDhKeyPair, entity));
    }

    @Test
    void verify_DhPubKeyFailed_Throws() throws Exception {
        // given
        mockAlias();
        when(response.getVerifierDhPubKey()).thenReturn(VERIFIER_DH);
        doThrow(new SigmaException("test")).when(dhPubKeyVerifier).verify(serviceDhKeyPair.getPublicKey(), VERIFIER_DH);

        // when-then
        Assertions.assertThrows(SigmaException.class, () -> sut.verify(response, serviceDhKeyPair, entity));
    }

    private void mockAlias() throws EcdhKeyPairException {
        when(entity.getAlias()).thenReturn(toHex(EcdhKeyPair.generate().getPublicKey()));
    }
}

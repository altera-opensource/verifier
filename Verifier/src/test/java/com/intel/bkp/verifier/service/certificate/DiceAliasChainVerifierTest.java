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

package com.intel.bkp.verifier.service.certificate;

import com.intel.bkp.verifier.exceptions.SigmaException;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import static com.intel.bkp.verifier.x509.X509CertificateExtendedKeyUsageVerifier.KEY_PURPOSE_ATTEST_INIT;
import static com.intel.bkp.verifier.x509.X509CertificateExtendedKeyUsageVerifier.KEY_PURPOSE_ATTEST_LOC;

@ExtendWith(MockitoExtension.class)
class DiceAliasChainVerifierTest {

    @Mock
    private ICrlProvider crlProvider;

    @Mock
    private RootHashVerifier rootHashVerifier;

    @InjectMocks
    private DiceAliasChainVerifier sut;

    @Test
    void getExpectedLeafCertKeyPurposes_ReturnsPurposesForAliasCertificate() {
        // given
        final String[] aliasCertificateKeyPurposes = new String[]{KEY_PURPOSE_ATTEST_INIT, KEY_PURPOSE_ATTEST_LOC};

        // when
        final String[] result = sut.getExpectedLeafCertKeyPurposes();

        // then
        Assertions.assertArrayEquals(aliasCertificateKeyPurposes, result);
    }

    @Test
    void handleVerificationFailure_throwsSigmaException() {
        // given
        final String failureDetails = "some details about why validation happened.";

        // when-then
        SigmaException ex = Assertions.assertThrows(SigmaException.class,
            () -> sut.handleVerificationFailure(failureDetails));

        // then
        Assertions.assertEquals(failureDetails, ex.getMessage());
    }
}

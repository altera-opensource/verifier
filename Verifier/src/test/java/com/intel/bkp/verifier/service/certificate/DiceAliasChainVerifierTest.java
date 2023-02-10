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

package com.intel.bkp.verifier.service.certificate;

import com.intel.bkp.fpgacerts.dice.tcbinfo.verification.FlagsVerifier;
import com.intel.bkp.fpgacerts.dice.tcbinfo.verification.ITcbInfoFieldVerifier;
import com.intel.bkp.fpgacerts.dice.tcbinfo.verification.TcbInfoVerifier;
import com.intel.bkp.fpgacerts.interfaces.ICrlProvider;
import com.intel.bkp.verifier.exceptions.VerifierRuntimeException;
import lombok.SneakyThrows;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.lang.reflect.Field;
import java.util.List;

import static com.intel.bkp.fpgacerts.model.Oid.KEY_PURPOSE_ATTEST_INIT;
import static com.intel.bkp.fpgacerts.model.Oid.KEY_PURPOSE_ATTEST_LOC;

@ExtendWith(MockitoExtension.class)
class DiceAliasChainVerifierTest {

    public static final String TRUSTED_ROOT_HASH = "someTrustedRootHash";
    public static final boolean TEST_MODE_SECRETS = true;

    @Mock
    private ICrlProvider crlProvider;

    private DiceAliasChainVerifier sut;

    @BeforeEach
    void setup() {
        sut = new DiceAliasChainVerifier(crlProvider, TRUSTED_ROOT_HASH, TEST_MODE_SECRETS);
    }

    @Test
    void constructor_configuresProperly() {
        // then
        Assertions.assertEquals(crlProvider, sut.getCrlVerifier().getCrlProvider());
        Assertions.assertEquals(TRUSTED_ROOT_HASH, sut.getTrustedRootHash());
        verifyTestModeSecretsInFlagsVerifier(TEST_MODE_SECRETS, sut.getTcbInfoVerifier());
    }

    @Test
    void getExpectedLeafCertKeyPurposes_ReturnsPurposesForAliasCertificate() {
        // given
        final String[] aliasCertificateKeyPurposes = new String[]{
            KEY_PURPOSE_ATTEST_INIT.getOid(),
            KEY_PURPOSE_ATTEST_LOC.getOid()
        };

        // when
        final String[] result = sut.getExpectedLeafCertKeyPurposes();

        // then
        Assertions.assertArrayEquals(aliasCertificateKeyPurposes, result);
    }

    @Test
    void handleVerificationFailure_throwsException() {
        // given
        final String failureDetails = "some details about why validation happened.";

        // when-then
        VerifierRuntimeException ex = Assertions.assertThrows(VerifierRuntimeException.class,
            () -> sut.handleVerificationFailure(failureDetails));

        // then
        Assertions.assertEquals(failureDetails, ex.getMessage());
    }

    @SuppressWarnings("unchecked")
    @SneakyThrows
    private void verifyTestModeSecretsInFlagsVerifier(boolean expectedTestModeSecrets,
                                                      TcbInfoVerifier tcbInfoVerifier) {
        final var flagsVerifier =
            ((List<ITcbInfoFieldVerifier>) getPrivateFieldValue("fieldVerifiers", tcbInfoVerifier)).stream()
                .filter(v -> v.getClass().equals(FlagsVerifier.class))
                .findAny()
                .get();

        final boolean actualTestModeSecrets = (boolean) getPrivateFieldValue("testModeSecrets", flagsVerifier);
        Assertions.assertEquals(expectedTestModeSecrets, actualTestModeSecrets);
    }

    @SneakyThrows
    private Object getPrivateFieldValue(String fieldName, Object obj) {
        final Field field = obj.getClass().getDeclaredField(fieldName);
        field.setAccessible(true);
        return field.get(obj);
    }
}

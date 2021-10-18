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

package com.intel.bkp.verifier.x509;

import com.intel.bkp.verifier.Utils;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import java.security.cert.X509Certificate;
import java.util.List;
import java.util.Set;

import static com.intel.bkp.verifier.model.AttestationOid.TCG_DICE_MULTI_TCB_INFO;
import static com.intel.bkp.verifier.model.AttestationOid.TCG_DICE_TCB_INFO;
import static com.intel.bkp.verifier.model.AttestationOid.TCG_DICE_UEID;

public class X509CertificateChainVerifierTestDiceIT {

    private static final String TEST_FOLDER = "certs/diceChain/";
    private static final X509CertificateParser X509_PARSER = new X509CertificateParser();
    private static final Set<String> DICE_EXTENSION_OIDS = Set.of(TCG_DICE_TCB_INFO.getOid(),
        TCG_DICE_MULTI_TCB_INFO.getOid(), TCG_DICE_UEID.getOid());

    private static X509Certificate aliasCert;
    private static X509Certificate firmwareCert;
    private static X509Certificate deviceIdCert;
    private static X509Certificate productFamilyCert;
    private static X509Certificate rootCert;

    private final X509CertificateChainVerifier sut = new X509CertificateChainVerifier();

    @BeforeAll
    static void init() throws Exception {
        aliasCert = X509_PARSER.toX509(getBytesFromFile("UDS_EFUSE_ALIAS_3AB5A0DC4DE7CB08.cer"));
        firmwareCert = X509_PARSER.toX509(getBytesFromFile("FIRMWARE_3AB5A0DC4DE7CB08.cer"));
        deviceIdCert = X509_PARSER.toX509(getBytesFromFile("deviceid_08cbe74ddca0b53a_7eukZEEF-nzSZWoH.cer"));
        productFamilyCert = X509_PARSER.toX509(getBytesFromFile("IPCS_agilex.cer"));
        rootCert = X509_PARSER.toX509(getBytesFromFile("DICE_RootCA.cer"));
    }

    private static byte[] getBytesFromFile(String filename) throws Exception {
        return Utils.readFromResources(TEST_FOLDER, filename);
    }

    @Test
    void verify_WithCorrectChain_WithCorrectDiceParameters_ReturnsTrue() {
        // given
        final var list = List.of(aliasCert, firmwareCert, deviceIdCert, productFamilyCert, rootCert);

        // when
        boolean result = sut.certificates(list)
            .knownExtensionOids(DICE_EXTENSION_OIDS)
            .verify();

        // then
        Assertions.assertTrue(result);
    }

    @Test
    void verify_WithCorrectChain_WithoutDiceExtensionOids_ReturnsFalse() {
        // given
        final var list = List.of(aliasCert, firmwareCert, deviceIdCert, productFamilyCert, rootCert);

        // when
        boolean result = sut.certificates(list).verify();

        // then
        Assertions.assertFalse(result);
    }

    @Test
    void verify_WithIncorrectChainMissingRoot_ReturnsFalse() {
        // given
        final var list = List.of(aliasCert, firmwareCert, deviceIdCert, productFamilyCert);

        // when
        boolean result = sut.certificates(list)
            .knownExtensionOids(DICE_EXTENSION_OIDS)
            .verify();

        // then
        Assertions.assertFalse(result);
    }
}

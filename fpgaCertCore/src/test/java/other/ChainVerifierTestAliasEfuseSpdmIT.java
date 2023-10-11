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

package other;

import com.intel.bkp.crypto.x509.validation.ChainVerifier;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import java.security.cert.X509Certificate;
import java.util.List;
import java.util.Set;

import static com.intel.bkp.fpgacerts.model.Oid.TCG_DICE_MULTI_TCB_INFO;
import static com.intel.bkp.fpgacerts.model.Oid.TCG_DICE_TCB_INFO;
import static com.intel.bkp.fpgacerts.model.Oid.TCG_DICE_UEID;
import static com.intel.bkp.test.CertificateUtils.readCertificate;
import static org.junit.jupiter.api.Assertions.assertTrue;

public class ChainVerifierTestAliasEfuseSpdmIT {

    private static final String ALIAS_EFUSE_SPDM_FOLDER = "certs/dice/aliasEfuseSpdmChain/";
    private static final String COMMON_FOLDER = "certs/dice/common/pre/";
    private static final Set<String> DICE_EXTENSION_OIDS = Set.of(TCG_DICE_TCB_INFO.getOid(),
        TCG_DICE_MULTI_TCB_INFO.getOid(), TCG_DICE_UEID.getOid());

    private static X509Certificate aliasCert;
    private static X509Certificate firmwareCert;
    private static X509Certificate deviceIdEnrollmentCert;
    private static X509Certificate deviceIdCert;
    private static X509Certificate enrollmentCert;
    private static X509Certificate productFamilyCert;
    private static X509Certificate rootCert;

    private final ChainVerifier sut = new ChainVerifier();

    @BeforeAll
    static void init() {
        aliasCert = readCertificate(ALIAS_EFUSE_SPDM_FOLDER, "alias_01458210996be470_spdm.cer");
        firmwareCert = readCertificate(ALIAS_EFUSE_SPDM_FOLDER, "firmware_01458210996be470_spdm.cer");
        deviceIdEnrollmentCert = readCertificate(ALIAS_EFUSE_SPDM_FOLDER, "deviceider_01458210996be470_spdm.cer");
        deviceIdCert = readCertificate(ALIAS_EFUSE_SPDM_FOLDER, "deviceId_01458210996be470_spdm.cer");
        enrollmentCert = readCertificate(ALIAS_EFUSE_SPDM_FOLDER, "M2284JP400295_enrol.der");
        productFamilyCert = readCertificate(COMMON_FOLDER, "IPCS_agilex.cer");
        rootCert = readCertificate(COMMON_FOLDER, "DICE_RootCA.cer");
    }

    @Test
    void verify_WithRealDeviceIdChain_ReturnsTrue() {
        // given
        final var chain = List.of(aliasCert, firmwareCert, deviceIdCert, productFamilyCert, rootCert);

        // when-then
        verify_WithDiceChain(chain);
    }

    @Test
    void verify_WithRealEnrollmentChain_ReturnsTrue() {
        // given
        final var chain =
            List.of(aliasCert, firmwareCert, deviceIdEnrollmentCert, enrollmentCert, productFamilyCert, rootCert);

        // when-then
        verify_WithDiceChain(chain);
    }

    private void verify_WithDiceChain(List<X509Certificate> chain) {
        // when
        boolean result = sut.certificates(chain)
            .knownExtensionOids(DICE_EXTENSION_OIDS)
            .verify();

        // then
        assertTrue(result);
    }
}

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

package com.intel.bkp.fpgacerts.dice.tcbinfo.verification;

import lombok.SneakyThrows;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.security.cert.X509Certificate;
import java.util.List;

import static com.intel.bkp.fpgacerts.Utils.readCertificate;

public class TcbInfoVerifierTestWithRealCertificates {

    private static final String ALIAS_EFUSE_FOLDER = "certs/dice/aliasEfuseChain/";
    private static final String ALIAS_EFUSE_SPDM_FOLDER = "certs/dice/aliasEfuseSpdmChain/";
    private static final String BKP_EFUSE_FOLDER = "certs/dice/bkpEfuseChain/";
    private static final String BKP_EFUSE_SPDM_FOLDER = "certs/dice/bkpEfuseSpdmChain/";
    private static final String COMMON_FOLDER = "certs/dice/common/";

    private static final String FAMILY_CERT = "IPCS_agilex.cer";
    private static final String ROOT_CERT = "DICE_RootCA.cer";

    private static X509Certificate productFamilyCert;
    private static X509Certificate rootCert;

    private TcbInfoVerifier sut;

    @BeforeAll
    static void loadCerts() throws Exception {
        productFamilyCert = readCertificate(COMMON_FOLDER, FAMILY_CERT);
        rootCert = readCertificate(COMMON_FOLDER, ROOT_CERT);
    }

    @BeforeEach
    void init() {
        sut = new TcbInfoVerifier();
    }

    @Test
    void verify_BkpEfuseChain_WithoutSPDM_Success() {
        verify_Success(prepareBkpEfuseChain());
    }

    @Test
    void verify_BkpEfuseChain_WithSPDM_Success() {
        verify_Success(prepareBkpEfuseChainWithSpdm());
    }

    @Test
    void verify_AliasEfuseChain_WithoutSPDM_Success() {
        verify_Success(prepareAliasEfuseChain());
    }

    @Test
    void verify_AliasEfuseChain_WithSPDM_Success() {
        verify_Success(prepareAliasEfuseChainWithSpdm());
    }

    private void verify_Success(List<X509Certificate> chain) {
        // when
        final boolean result = sut.certificates(chain).verify();

        // then
        Assertions.assertTrue(result);
    }

    @SneakyThrows
    private List<X509Certificate> prepareBkpEfuseChain() {
        final String folder = BKP_EFUSE_FOLDER;
        final X509Certificate bkpCert = readCertificate(folder, "bkp_08cbe34bcc8ae220.cer");
        final X509Certificate firmwareCert = readCertificate(folder, "firmware_08cbe34bcc8ae220.cer");
        final X509Certificate deviceIdCert = readCertificate(folder,
            "deviceid_08cbe34bcc8ae220_K2y37QKWArzRKYWZZ-iwal07elk.cer");
        return List.of(bkpCert, firmwareCert, deviceIdCert, productFamilyCert, rootCert);
    }

    @SneakyThrows
    private List<X509Certificate> prepareBkpEfuseChainWithSpdm() {
        final String folder = BKP_EFUSE_SPDM_FOLDER;
        final X509Certificate bkpCert = readCertificate(folder, "uds_efuse_black_key_certificate.der");
        final X509Certificate firmwareCert = readCertificate(folder, "firmware_certificate.der");
        final X509Certificate deviceIdCert = readCertificate(folder, "M2284JP400295_devID.der");
        return List.of(bkpCert, firmwareCert, deviceIdCert, productFamilyCert, rootCert);
    }

    @SneakyThrows
    private List<X509Certificate> prepareAliasEfuseChain() {
        final String folder = ALIAS_EFUSE_FOLDER;
        final X509Certificate aliasCert = readCertificate(folder, "UDS_EFUSE_ALIAS_3AB5A0DC4DE7CB08.cer");
        final X509Certificate firmwareCert = readCertificate(folder, "FIRMWARE_3AB5A0DC4DE7CB08.cer");
        final X509Certificate deviceIdCert = readCertificate(folder,
            "deviceid_08cbe74ddca0b53a_7eukZEEF-nzSZWoHQrqQf53ru9A.cer");
        return List.of(aliasCert, firmwareCert, deviceIdCert, productFamilyCert, rootCert);
    }

    @SneakyThrows
    private List<X509Certificate> prepareAliasEfuseChainWithSpdm() {
        final String folder = ALIAS_EFUSE_SPDM_FOLDER;
        final X509Certificate aliasCert = readCertificate(folder, "alias_01458210996be470_spdm.cer");
        final X509Certificate firmwareCert = readCertificate(folder, "firmware_01458210996be470_spdm.cer");
        final X509Certificate deviceIdCert = readCertificate(folder,
            "deviceId_01458210996be470_spdm.cer");
        return List.of(aliasCert, firmwareCert, deviceIdCert, productFamilyCert, rootCert);
    }
}

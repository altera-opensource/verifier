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

import com.intel.bkp.fpgacerts.interfaces.ICrlProvider;
import lombok.SneakyThrows;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.security.cert.X509CRL;
import java.security.cert.X509Certificate;
import java.util.List;

import static com.intel.bkp.utils.HexConverter.fromHex;
import static com.intel.bkp.verifier.Utils.readCertificate;
import static com.intel.bkp.verifier.Utils.readCrl;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
public class DiceAliasChainVerifierTestWithRealCertificates {

    private static final String DICE_ROOT_HASH = "35E08599DD52CB7533764DEE65C915BBAFD0E35E6252BCCD77F3A694390F618B";
    private static final String DICE_ROOT_HASH_PRE = "9DB7D8D004D650B40ED993F2B665E19DA65BD065D7BBD35D6C1439C4B4201259";

    private static final String ALIAS_EFUSE_FOLDER = "certs/dice/aliasEfuseChain/";
    private static final String ALIAS_EFUSE_SPDM_FOLDER = "certs/dice/aliasEfuseSpdmChain/";
    private static final String COMMON_FOLDER = "certs/dice/common/";
    private static final String COMMON_PRE_FOLDER = "certs/dice/common/pre/";
    private static final String FAMILY_CERT = "IPCS_agilex.cer";
    private static final String FAMILY_CRL = "IPCS_agilex.crl";
    private static final String FAMILY_CRL_L1 = "IPCS_agilex_L1.crl";
    private static final String ROOT_CERT = "DICE_RootCA.cer";
    private static final String ROOT_CRL = "DICE.crl";

    @Mock
    private ICrlProvider crlProvider;

    private DiceAliasChainVerifier sut;

    @Test
    void verify_EfuseChain_WithoutSpdm_Success() {
        // given
        final var chain = prepareAliasEfuseChain();
        final String deviceId = "3AB5A0DC4DE7CB08";
        sut = prepareSutForProductionChain();
        sut.setDeviceId(fromHex(deviceId));

        // when-then
        Assertions.assertDoesNotThrow(() -> sut.verifyChain(chain));
    }

    @Test
    void verify_EfuseChain_WithSpdm_Success() {
        // given
        final var chain = prepareAliasEfuseChainWithSpdm();
        final String deviceId = "70E46B9910824501";
        sut = prepareSutForPreProductionChain();
        sut.setDeviceId(fromHex(deviceId));

        // when-then
        Assertions.assertDoesNotThrow(() -> sut.verifyChain(chain));
    }

    @SneakyThrows
    private List<X509Certificate> prepareAliasEfuseChain() {
        final String folder = ALIAS_EFUSE_FOLDER;
        final X509Certificate aliasCert = readCertificate(folder, "UDS_EFUSE_ALIAS_3AB5A0DC4DE7CB08.cer");
        final X509Certificate firmwareCert = readCertificate(folder, "FIRMWARE_3AB5A0DC4DE7CB08.cer");
        final X509Certificate deviceIdCert = readCertificate(folder,
            "deviceid_08cbe74ddca0b53a_7eukZEEF-nzSZWoHQrqQf53ru9A.cer");
        final X509Certificate productFamilyCert = readCertificate(COMMON_FOLDER, FAMILY_CERT);
        final X509Certificate rootCert = readCertificate(COMMON_FOLDER, ROOT_CERT);
        return List.of(aliasCert, firmwareCert, deviceIdCert, productFamilyCert, rootCert);
    }

    @SneakyThrows
    private List<X509Certificate> prepareAliasEfuseChainWithSpdm() {
        final String folder = ALIAS_EFUSE_SPDM_FOLDER;
        final X509Certificate aliasCert = readCertificate(folder, "alias_01458210996be470_spdm.cer");
        final X509Certificate firmwareCert = readCertificate(folder, "firmware_01458210996be470_spdm.cer");
        final X509Certificate deviceIdCert = readCertificate(folder,
            "deviceId_01458210996be470_spdm.cer");
        final X509Certificate productFamilyCert = readCertificate(COMMON_PRE_FOLDER, FAMILY_CERT);
        final X509Certificate rootCert = readCertificate(COMMON_PRE_FOLDER, ROOT_CERT);
        return List.of(aliasCert, firmwareCert, deviceIdCert, productFamilyCert, rootCert);
    }

    @SneakyThrows
    private DiceAliasChainVerifier prepareSutForProductionChain() {
        final String folder = COMMON_FOLDER;
        final X509CRL familyL1Crl = readCrl(folder, FAMILY_CRL_L1);
        final X509CRL familyCrl = readCrl(folder, FAMILY_CRL);
        final X509CRL rootCrl = readCrl(folder, ROOT_CRL);
        mockCrls(true, familyL1Crl, familyCrl, rootCrl);
        return new DiceAliasChainVerifier(crlProvider, DICE_ROOT_HASH);
    }

    @SneakyThrows
    private DiceAliasChainVerifier prepareSutForPreProductionChain() {
        final String folder = COMMON_PRE_FOLDER;
        final X509CRL familyL1Crl = readCrl(folder, FAMILY_CRL_L1);
        final X509CRL familyCrl = readCrl(folder, FAMILY_CRL);
        final X509CRL rootCrl = readCrl(folder, ROOT_CRL);
        mockCrls(false, familyL1Crl, familyCrl, rootCrl);
        return new DiceAliasChainVerifier(crlProvider, DICE_ROOT_HASH_PRE);
    }

    private void mockCrls(boolean isProduction, X509CRL familyL1Crl, X509CRL familyCrl, X509CRL rootCrl) {
        final String productionDpUrl = "https://tsci.intel.com";
        final String preProductionDpUrl = "https://pre1-tsci.intel.com";
        final String dpUrl = isProduction ? productionDpUrl : preProductionDpUrl;
        // Note that L1 CRL is pointed by firmware certificate issued on FPGA device, so it is always downloaded from
        //  production DP - but to enable test with preproduction chain to pass, preProduction L1 CRL must be returned.
        //  This trick is only for test purpose - in reality chain validation with preProduction certs will fail.
        mockCrlProvider(productionDpUrl + "/content/IPCS/crls/IPCS_agilex_L1.crl", familyL1Crl);
        mockCrlProvider(dpUrl + "/content/IPCS/crls/IPCS_agilex.crl", familyCrl);
        mockCrlProvider(dpUrl + "/content/DICE/crls/DICE.crl", rootCrl);
    }

    private void mockCrlProvider(String url, X509CRL crl) {
        when(crlProvider.getCrl(url)).thenReturn(crl);
    }
}

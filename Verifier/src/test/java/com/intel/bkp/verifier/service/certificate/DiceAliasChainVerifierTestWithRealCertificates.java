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

package com.intel.bkp.verifier.service.certificate;

import com.intel.bkp.fpgacerts.interfaces.ICrlProvider;
import lombok.Getter;
import lombok.RequiredArgsConstructor;
import lombok.SneakyThrows;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.EnumSource;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.security.cert.X509CRL;
import java.security.cert.X509Certificate;
import java.util.List;

import static com.intel.bkp.test.CertificateUtils.readCertificate;
import static com.intel.bkp.test.CertificateUtils.readCrl;
import static com.intel.bkp.utils.HexConverter.fromHex;
import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
public class DiceAliasChainVerifierTestWithRealCertificates {

    @Getter
    @RequiredArgsConstructor
    private enum ChainParams {
        FM_BEFORE_SPDM(true, EFUSE_BEFORE_SPDM_FOLDER, "agilex", "3AB5A0DC4DE7CB08",
            "UDS_EFUSE_ALIAS_3AB5A0DC4DE7CB08.cer",
            "FIRMWARE_3AB5A0DC4DE7CB08.cer",
            "deviceid_08cbe74ddca0b53a_7eukZEEF-nzSZWoHQrqQf53ru9A.cer",
            false),
        FM(false, EFUSE_FOLDER, "agilex", "70E46B9910824501",
            "alias_01458210996be470_spdm.cer",
            "firmware_01458210996be470_spdm.cer",
            "deviceId_01458210996be470_spdm.cer",
            false),
        SM(false, SM_EFUSE_FOLDER, "agilexb", "5AECAC18CCC68207",
            "alias_0782c6cc18acec5a_sm.cer",
            "firmware_0782c6cc18acec5a_sm.cer",
            "ipcs_deviceId_0782c6cc18acec5a_sm.cer",
            true);


        final boolean isProduction;
        final String folder;
        final String familyName;
        final String deviceId;
        final String aliasCertFileName;
        final String fwCertFileName;
        final String deviceIdCertFileName;
        final boolean testModeSecrets;

    }

    public static final String PRODUCTION_DP_URL = "https://tsci.intel.com";
    public static final String PRE_PRODUCTION_DP_URL = "https://pre1-tsci.intel.com";
    private static final String DICE_ROOT_HASH = "35E08599DD52CB7533764DEE65C915BBAFD0E35E6252BCCD77F3A694390F618B";
    private static final String DICE_ROOT_HASH_PRE = "9DB7D8D004D650B40ED993F2B665E19DA65BD065D7BBD35D6C1439C4B4201259";
    private static final String EFUSE_BEFORE_SPDM_FOLDER = "certs/dice/aliasEfuseChain/";
    private static final String EFUSE_FOLDER = "certs/dice/aliasEfuseSpdmChain/";
    private static final String SM_EFUSE_FOLDER = EFUSE_FOLDER + "sm/";
    private static final String COMMON_FOLDER = "certs/dice/common/";
    private static final String COMMON_PRE_FOLDER = COMMON_FOLDER + "pre/";
    private static final String FAMILY_CERT_FORMAT = "IPCS_%s.cer";
    private static final String FAMILY_CRL_FORMAT = "IPCS_%s.crl";
    private static final String FAMILY_CRL_L1_FORMAT = "IPCS_%s_L1.crl";
    private static final String ROOT_CERT = "DICE_RootCA.cer";
    private static final String ROOT_CRL = "DICE.crl";

    @Mock
    private ICrlProvider crlProvider;

    private DiceAliasChainVerifier sut;

    @ParameterizedTest
    @EnumSource(ChainParams.class)
    void verifyChain_Success(ChainParams chainParams) {
        // given
        final var chain = prepareChain(chainParams);
        mockCrls(chainParams);
        sut = prepareSut(chainParams);
        sut.setDeviceId(fromHex(chainParams.getDeviceId()));

        // when-then
        assertDoesNotThrow(() -> sut.verifyChain(chain));
    }

    @SneakyThrows
    private List<X509Certificate> prepareChain(ChainParams chainParams) {
        final String folder = chainParams.getFolder();
        final X509Certificate aliasCert = readCertificate(folder, chainParams.getAliasCertFileName());
        final X509Certificate firmwareCert = readCertificate(folder, chainParams.getFwCertFileName());
        final X509Certificate deviceIdCert = readCertificate(folder, chainParams.getDeviceIdCertFileName());

        final String commonFolder = chainParams.isProduction() ? COMMON_FOLDER : COMMON_PRE_FOLDER;
        final String familyCertFileName = FAMILY_CERT_FORMAT.formatted(chainParams.getFamilyName());
        final X509Certificate productFamilyCert = readCertificate(commonFolder, familyCertFileName);
        final X509Certificate rootCert = readCertificate(commonFolder, ROOT_CERT);

        return List.of(aliasCert, firmwareCert, deviceIdCert, productFamilyCert, rootCert);
    }

    private DiceAliasChainVerifier prepareSut(ChainParams chainParams) {
        final var trustedRootHash = chainParams.isProduction() ? DICE_ROOT_HASH : DICE_ROOT_HASH_PRE;
        return new DiceAliasChainVerifier(crlProvider, new String[]{trustedRootHash}, chainParams.isTestModeSecrets());
    }

    @SneakyThrows
    private void mockCrls(ChainParams chainParams) {
        final String familyName = chainParams.getFamilyName();
        final String folder = chainParams.isProduction() ? COMMON_FOLDER : COMMON_PRE_FOLDER;
        final X509CRL familyL1Crl = readCrl(folder, FAMILY_CRL_L1_FORMAT.formatted(familyName));
        final X509CRL familyCrl = readCrl(folder, FAMILY_CRL_FORMAT.formatted(familyName));
        final X509CRL rootCrl = readCrl(folder, ROOT_CRL);

        final String dpUrl = chainParams.isProduction() ? PRODUCTION_DP_URL : PRE_PRODUCTION_DP_URL;
        // Note that L1 CRL is pointed by firmware certificate issued on FPGA device, so it is always downloaded from
        //  production DP - but to enable test with preproduction chain to pass, preProduction L1 CRL must be returned.
        //  This trick is only for test purpose - in reality chain validation with preProduction certs will fail.
        mockCrlProvider(PRODUCTION_DP_URL + "/content/IPCS/crls/IPCS_%s_L1.crl".formatted(familyName), familyL1Crl);
        mockCrlProvider(dpUrl + "/content/IPCS/crls/IPCS_%s.crl".formatted(familyName), familyCrl);
        mockCrlProvider(dpUrl + "/content/DICE/crls/DICE.crl", rootCrl);
    }

    private void mockCrlProvider(String url, X509CRL crl) {
        when(crlProvider.getCrl(url)).thenReturn(crl);
    }
}

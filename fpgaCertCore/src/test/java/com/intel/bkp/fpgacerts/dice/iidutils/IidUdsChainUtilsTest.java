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

package com.intel.bkp.fpgacerts.dice.iidutils;

import com.intel.bkp.fpgacerts.Utils;
import lombok.SneakyThrows;
import org.junit.jupiter.api.Test;

import java.security.cert.X509Certificate;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

class IidUdsChainUtilsTest {

    private static final String TEST_FOLDER = "certs/dice/";
    private static final String EFUSE_CERT = "aliasEfuseSpdmChain/alias_01458210996be470_spdm.cer";
    private static final String IIDUDS_CERT = "IID/uds_iidpuf_alias_certificate.der";

    @Test
    void isIidUdsChain_ForIidCert_ReturnsTrue() {
        // given
        final List<X509Certificate> chain = prepareIidChain();

        // when
        final boolean result = IidUdsChainUtils.isIidUdsChain(chain);

        // then
        assertTrue(result);
    }

    @Test
    void isIidUdsChain_ForEfuseCert_ReturnsFalse() {
        // given
        final List<X509Certificate> chain = prepareEfuseChain();

        // when
        final boolean result = IidUdsChainUtils.isIidUdsChain(chain);

        // then
        assertFalse(result);
    }

    private List<X509Certificate> prepareIidChain() {
        return prepareChain(IIDUDS_CERT);
    }

    private List<X509Certificate> prepareEfuseChain() {
        return prepareChain(EFUSE_CERT);
    }

    @SneakyThrows
    private static List<X509Certificate> prepareChain(String filename) {
        return List.of(Utils.readCertificate(TEST_FOLDER, filename));
    }
}

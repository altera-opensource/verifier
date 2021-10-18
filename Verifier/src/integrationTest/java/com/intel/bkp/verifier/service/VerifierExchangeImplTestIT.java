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

package com.intel.bkp.verifier.service;

import com.intel.bkp.ext.core.security.ISecurityProvider;
import com.intel.bkp.ext.core.security.SecurityProviderParams;
import com.intel.bkp.ext.core.security.SecurityProviderParamsSetter;
import com.intel.bkp.ext.crypto.constants.SecurityKeyType;
import com.intel.bkp.verifier.config.JceSecurityConfiguration;
import com.intel.bkp.verifier.model.VerifierExchangeResponse;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

public class VerifierExchangeImplTestIT {

    private static final int PORT = 9001;
    private static final int INVALID_PORT = 9999;
    private static final String HPS_TRANSPORT_ID = "host:localhost;port:";
    private static final SecurityProviderParams securityProviderParams =
        SecurityProviderParamsSetter.setDefaultSecurityProviderParams();
    private static final String KEY_NAME = "VERIFIER_KEY_NAME";

    private static final SimpleSocketServer server = new SimpleSocketServer(PORT);
    private static final ISecurityProvider securityProvider = new JceSecurityConfiguration()
        .getSecurityProvider(securityProviderParams);

    private VerifierExchangeImpl sut;

    @BeforeAll
    static void init() {
        server.startServer();
        prepareVerifierKey();
    }

    private static void prepareVerifierKey() {
        if (!securityProvider.existsSecurityObject(KEY_NAME)) {
            securityProvider.createSecurityObject(SecurityKeyType.EC, KEY_NAME);
        }
    }

    private static void removeVerifierKey() {
        if (securityProvider.existsSecurityObject(KEY_NAME)) {
            securityProvider.deleteSecurityObject(KEY_NAME);
        }
    }

    @AfterAll
    static void clean() {
        server.stopServer();
    }

    @BeforeEach
    void setUp() {
        sut = new VerifierExchangeImpl();
    }

    @Test
    void healthCheck_ReturnsOk() {
        // given
        prepareVerifierKey();

        // when
        final int result = sut.healthCheck(HPS_TRANSPORT_ID + PORT);

        // then
        Assertions.assertEquals(VerifierExchangeResponse.OK.getCode(), result);
    }

    @Test
    void healthCheck_KeyNotInSecurityEnclave_ReturnsError() {
        // given
        removeVerifierKey();

        // when
        final int result = sut.healthCheck(HPS_TRANSPORT_ID + PORT);

        // then
        Assertions.assertEquals(VerifierExchangeResponse.ERROR.getCode(), result);
    }

    @Test
    void healthCheck_InvalidPort_ReturnsError() {
        // when
        final int result = sut.healthCheck(HPS_TRANSPORT_ID + INVALID_PORT);

        // then
        Assertions.assertEquals(VerifierExchangeResponse.ERROR.getCode(), result);
    }
}

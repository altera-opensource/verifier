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

package com.intel.bkp.fpgacerts.dp;

import com.intel.bkp.fpgacerts.dp.proxy.IProxyCallback;
import com.intel.bkp.fpgacerts.dp.proxy.ProxyCallbackFactory;
import com.intel.bkp.fpgacerts.dp.proxy.ProxyCallbackImplCustom;
import com.intel.bkp.fpgacerts.dp.proxy.ProxyCallbackImplDefault;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.junit.jupiter.MockitoExtension;

import static org.junit.jupiter.api.Assertions.assertTrue;

@ExtendWith(MockitoExtension.class)
class ProxyCallbackFactoryTest {

    @Test
    void get_WithHostAndPort_ReturnsCustom() {
        // given
        final String host = "test";
        final int port = 123;

        // when
        final IProxyCallback result = ProxyCallbackFactory.get(host, port);

        // then
        assertTrue(result instanceof ProxyCallbackImplCustom);
    }

    @Test
    void get_WithHostEmpty_ReturnsDefault() {
        // given
        final String host = "";
        final int port = 123;

        // when
        final IProxyCallback result = ProxyCallbackFactory.get(host, port);

        // then
        assertTrue(result instanceof ProxyCallbackImplDefault);
    }

    @Test
    void get_WithHostNull_ReturnsDefault() {
        // given
        final String host = null;
        final int port = 123;

        // when
        final IProxyCallback result = ProxyCallbackFactory.get(host, port);

        // then
        assertTrue(result instanceof ProxyCallbackImplDefault);
    }

    @Test
    void get_WithPortNull_ReturnsDefault() {
        // given
        final String host = "test";
        final Integer port = null;

        // when
        final IProxyCallback result = ProxyCallbackFactory.get(host, port);

        // then
        assertTrue(result instanceof ProxyCallbackImplDefault);
    }

    @Test
    void get_WithPortZero_ReturnsDefault() {
        // given
        final String host = "test";
        final Integer port = 0;

        // when
        final IProxyCallback result = ProxyCallbackFactory.get(host, port);

        // then
        assertTrue(result instanceof ProxyCallbackImplDefault);
    }
}

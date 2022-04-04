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

import com.intel.bkp.core.properties.Proxy;
import com.intel.bkp.crypto.exceptions.X509CrlParsingException;
import com.intel.bkp.fpgacerts.interfaces.ICrlProvider;
import com.intel.bkp.verifier.dp.DistributionPointConnector;
import com.intel.bkp.verifier.exceptions.X509ParsingException;
import lombok.AccessLevel;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;

import java.security.cert.X509CRL;

import static com.intel.bkp.crypto.x509.parsing.X509CrlParser.toX509Crl;

@Slf4j
@RequiredArgsConstructor(access = AccessLevel.PACKAGE)
public class DistributionPointCrlProvider implements ICrlProvider {

    private final DistributionPointConnector connector;

    public DistributionPointCrlProvider(Proxy proxy) {
        this(new DistributionPointConnector(proxy));
    }

    @Override
    public X509CRL getCrl(String crlUrl) {
        final byte[] crlBytes = connector.getBytes(crlUrl);
        try {
            return toX509Crl(crlBytes);
        } catch (X509CrlParsingException e) {
            throw new X509ParsingException(String.format("Failed to parse CRL downloaded from %s", crlUrl), e);
        }
    }
}

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

package com.intel.bkp.test;

import com.intel.bkp.crypto.x509.generation.ICrlParams;
import com.intel.bkp.crypto.x509.generation.X509CrlIssuerDTO;
import org.bouncycastle.cert.X509v2CRLBuilder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

import java.math.BigInteger;
import java.security.KeyPair;
import java.util.Date;

import static com.intel.bkp.utils.X509DateBuilderHelper.notAfter;

public class CrlParamsUtil implements ICrlParams {

    private static final int VALIDITY_HOURS = 24;
    private final BigInteger crlNumber = BigInteger.ZERO;

    private final X509CrlIssuerDTO issuerDTO;

    public CrlParamsUtil() {
        final KeyPair keyPair = KeyGenUtils.genEc384();
        assert keyPair != null;
        this.issuerDTO = new X509CrlIssuerDTO(CertificateUtils.generateCertificate(), keyPair.getPrivate(),
            new BouncyCastleProvider());
    }

    @Override
    public X509CrlIssuerDTO getIssuer() {
        return issuerDTO;
    }

    @Override
    public BigInteger getCrlNumber() {
        return crlNumber;
    }

    @Override
    public Date getNextUpdate(Date now) {
        return notAfter(now, VALIDITY_HOURS);
    }

    @Override
    public void fillEntries(X509v2CRLBuilder crlBuilder) {

    }
}

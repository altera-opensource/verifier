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

package com.intel.bkp.crypto.x509.generation;

import lombok.Getter;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;

import java.math.BigInteger;
import java.security.PublicKey;
import java.util.Date;
import java.util.Random;

import static com.intel.bkp.utils.X509DateBuilderHelper.notAfter;
import static com.intel.bkp.utils.X509DateBuilderHelper.notBefore;

@Getter
public class X509CertificateBuilderParams {

    private final PublicKey publicKey;

    private BigInteger serialNumber;
    private X500Name issuerName;
    private X500Name subjectName;
    private Date notBefore;
    private Date notAfter;

    public X509CertificateBuilderParams(PublicKey publicKey) {
        this.publicKey = publicKey;

        this.serialNumber = generateSerialNumber();
        this.issuerName = getDefaultDummyX500Name();
        this.subjectName = getDefaultDummyX500Name();
        this.notBefore = notBefore();
        this.notAfter = notAfter();
    }

    public X509CertificateBuilderParams withSerialNumber(BigInteger serialNumber) {
        this.serialNumber = serialNumber;
        return this;
    }

    public X509CertificateBuilderParams withIssuerName(X500Name issuerName) {
        this.issuerName = issuerName;
        return this;
    }

    public X509CertificateBuilderParams withSubjectName(X500Name subjectName) {
        this.subjectName = subjectName;
        return this;
    }

    public X509CertificateBuilderParams withNotBefore(Date notBefore) {
        this.notBefore = notBefore;
        return this;
    }

    public X509CertificateBuilderParams withNotAfter(Date notAfter) {
        this.notAfter = notAfter;
        return this;
    }

    public JcaX509v3CertificateBuilder getBuilder() {
        return new JcaX509v3CertificateBuilder(issuerName, serialNumber, notBefore, notAfter, subjectName, publicKey);
    }

    private BigInteger generateSerialNumber() {
        return BigInteger.valueOf(new Random().nextInt());
    }

    private X500Name getDefaultDummyX500Name() {
        return new X500Name("CN=localhost, O=FOO, L=BAR, ST=BAZ, C=QUX");
    }
}

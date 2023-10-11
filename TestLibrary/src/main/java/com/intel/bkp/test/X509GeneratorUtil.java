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

import com.intel.bkp.crypto.CryptoUtils;
import com.intel.bkp.crypto.exceptions.CrlGenerationFailed;
import com.intel.bkp.crypto.x509.generation.ICrlParams;
import com.intel.bkp.crypto.x509.generation.X509CertificateBuilder;
import com.intel.bkp.crypto.x509.generation.X509CertificateBuilderParams;
import com.intel.bkp.crypto.x509.generation.X509CrlGenerator;
import com.intel.bkp.crypto.x509.generation.X509CrlIssuerDTO;
import com.intel.bkp.crypto.x509.utils.X509CrlUtils;
import com.intel.bkp.test.model.SerialNumberCrlParams;
import lombok.Getter;
import lombok.Setter;

import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.Provider;
import java.security.PublicKey;
import java.security.cert.X509CRL;
import java.security.cert.X509Certificate;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Date;
import java.util.List;
import java.util.Optional;

import static com.intel.bkp.crypto.x509.utils.X509CertificateUtils.toPem;
import static com.intel.bkp.utils.X509DateBuilderHelper.notAfter;
import static org.bouncycastle.asn1.x509.KeyPurposeId.anyExtendedKeyUsage;
import static org.bouncycastle.asn1.x509.KeyPurposeId.id_kp_clientAuth;
import static org.bouncycastle.asn1.x509.KeyPurposeId.id_kp_serverAuth;
import static org.bouncycastle.asn1.x509.KeyUsage.cRLSign;
import static org.bouncycastle.asn1.x509.KeyUsage.dataEncipherment;
import static org.bouncycastle.asn1.x509.KeyUsage.digitalSignature;
import static org.bouncycastle.asn1.x509.KeyUsage.keyCertSign;
import static org.bouncycastle.asn1.x509.KeyUsage.keyEncipherment;

@Getter
public class X509GeneratorUtil {

    private final Provider provider = CryptoUtils.getBouncyCastleProvider();

    private KeyPair leafKeyPair;
    private KeyPair rootKeyPair;
    private X509Certificate rootCertificate;
    private X509Certificate leafCertificate;
    @Setter
    private int certValidityYears = 3;

    public String generateX509Chain() throws Exception {
        return String.join(System.lineSeparator(), generateX509ChainStringArray());
    }

    public String[] generateX509ChainStringArray() throws Exception {
        rootKeyPair = KeyGenUtils.genEc384();
        final KeyPair interGen = KeyGenUtils.genEc384();
        leafKeyPair = KeyGenUtils.genEc384();

        rootCertificate = createCert(rootKeyPair.getPublic(), rootKeyPair.getPrivate());
        X509Certificate middleCertificate = createCert(interGen.getPublic(), rootKeyPair.getPrivate());
        leafCertificate = createCert(leafKeyPair.getPublic(), interGen.getPrivate());

        return new String[]{
            toPem(leafCertificate),
            toPem(middleCertificate),
            toPem(rootCertificate)
        };
    }

    public List<X509Certificate> generateX509ChainList() throws Exception {
        rootKeyPair = KeyGenUtils.genEc384();
        final KeyPair interGen = KeyGenUtils.genEc384();
        leafKeyPair = KeyGenUtils.genEc384();
        final var list = new ArrayList<X509Certificate>();
        list.add(createCert(leafKeyPair.getPublic(), interGen.getPrivate()));
        list.add(createCert(interGen.getPublic(), rootKeyPair.getPrivate()));
        list.add(createCert(rootKeyPair.getPublic(), rootKeyPair.getPrivate()));

        return list;
    }

    public List<String> generateX509ChainForCaService(PublicKey leafCertificatePubKey) throws Exception {
        rootKeyPair = KeyGenUtils.genEc384();
        rootCertificate = createCert(rootKeyPair.getPublic(), rootKeyPair.getPrivate());
        X509Certificate leafCertificate = createCert(leafCertificatePubKey, rootKeyPair.getPrivate());
        return Arrays.asList(toPem(leafCertificate), "\n", toPem(rootCertificate));
    }

    public String generateX509CrlForCaService() throws Exception {
        rootKeyPair = KeyGenUtils.genEc384();
        rootCertificate = createCert(rootKeyPair.getPublic(), rootKeyPair.getPrivate());
        final var issuer = new X509CrlIssuerDTO(rootCertificate, rootKeyPair.getPrivate(), provider);
        final ICrlParams crlParams = new SerialNumberCrlParams(issuer, new ArrayList<>());
        final X509CRL crl = X509CrlGenerator.generateCrl(crlParams);
        return X509CrlUtils.toPem(crl);
    }

    private X509Certificate createCert(PublicKey publicKey, PrivateKey privateKey) throws Exception {
        final var params = new X509CertificateBuilderParams(publicKey)
            .withNotAfter(notAfter(certValidityYears));

        final var builder = new X509CertificateBuilder(params)
            .withSubjectKeyIdentifier()
            .withBasicConstraintsForIssuerCertWithUnlimitedPathLength()
            .withKeyUsage(keyCertSign | digitalSignature | keyEncipherment | dataEncipherment | cRLSign)
            .withExtendedKeyUsage(id_kp_serverAuth, id_kp_clientAuth, anyExtendedKeyUsage);

        return builder.sign(privateKey);
    }

    public static X509CRL generateCrl(Optional<Date> nowOptional) throws CrlGenerationFailed {
        final CrlParamsUtil crlParams = new CrlParamsUtil();
        return X509CrlGenerator.generateCrl(crlParams, nowOptional);

    }

    public static X509CRL generateCrl() throws CrlGenerationFailed {
        return generateCrl(Optional.of(new Date()));
    }

    public static X509CRL generateExpiredCrl() throws CrlGenerationFailed {
        final var expiredDate = Optional.of(Date.from(Instant.now().minus(100, ChronoUnit.DAYS)));
        return generateCrl(expiredDate);
    }

    public static X509CRL generateCrlWithoutNextUpdate() throws CrlGenerationFailed {
        return generateCrl(Optional.empty());
    }
}

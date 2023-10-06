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
import com.intel.bkp.crypto.x509.generation.ICrlParams;
import com.intel.bkp.crypto.x509.generation.X509CertificateBuilder;
import com.intel.bkp.crypto.x509.generation.X509CertificateBuilderParams;
import com.intel.bkp.crypto.x509.generation.X509CrlGenerator;
import com.intel.bkp.crypto.x509.generation.X509CrlIssuerDTO;
import com.intel.bkp.test.model.SerialNumberCrlParams;
import lombok.Getter;
import lombok.Setter;

import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.Provider;
import java.security.PublicKey;
import java.security.cert.X509CRL;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

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
public class DiceX509GeneratorUtil {

    private final Provider provider = CryptoUtils.getBouncyCastleProvider();

    private KeyPair rootKeyPair;
    private X509Certificate rootCertificate;
    @Setter
    private int certValidityYears = 3;

    private final String dpCrlUrl = "https://pre1-tsci.intel.com/content/IPCS/crls/IPCS_agilex.crl";
    private final String dpCerUrl = "https://pre1-tsci.intel.com/content/IPCS/certs/IPCS_agilex.cer";

    public List<byte[]> generateX509ChainForCaServiceDer(PublicKey leafCertificatePubKey) throws Exception {
        rootKeyPair = KeyGenUtils.genEc384();
        rootCertificate = createCert(rootKeyPair.getPublic(), rootKeyPair.getPrivate());
        X509Certificate leafCertificate = createCert(leafCertificatePubKey, rootKeyPair.getPrivate());
        return Arrays.asList(leafCertificate.getEncoded(), rootCertificate.getEncoded());
    }

    public byte[] generateX509CrlForCaServiceDer() throws Exception {
        final var issuer = new X509CrlIssuerDTO(rootCertificate, rootKeyPair.getPrivate(), provider);
        final ICrlParams crlParams = new SerialNumberCrlParams(issuer, new ArrayList<>());
        final X509CRL crl = X509CrlGenerator.generateCrl(crlParams);
        return crl.getEncoded();
    }

    private X509Certificate createCert(PublicKey publicKey, PrivateKey privateKey) throws Exception {
        final var params = new X509CertificateBuilderParams(publicKey)
            .withNotAfter(notAfter(certValidityYears));

        final var builder = new X509CertificateBuilder(params)
            .withSubjectKeyIdentifier()
            .withCrlDistributionPoints(getDpCrlUrl())
            .withAuthorityInfoAccess(getDpCerUrl())
            .withBasicConstraintsForIssuerCertWithUnlimitedPathLength()
            .withKeyUsage(keyCertSign | digitalSignature | keyEncipherment | dataEncipherment | cRLSign)
            .withExtendedKeyUsage(id_kp_serverAuth, id_kp_clientAuth, anyExtendedKeyUsage);

        return builder.sign(privateKey);
    }
}

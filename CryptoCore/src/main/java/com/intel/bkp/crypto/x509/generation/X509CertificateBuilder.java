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

import com.intel.bkp.crypto.CryptoUtils;
import com.intel.bkp.crypto.constants.CryptoConstants;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.x509.AuthorityInformationAccess;
import org.bouncycastle.asn1.x509.AuthorityKeyIdentifier;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.CRLDistPoint;
import org.bouncycastle.asn1.x509.DistributionPoint;
import org.bouncycastle.asn1.x509.DistributionPointName;
import org.bouncycastle.asn1.x509.ExtendedKeyUsage;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.GeneralNames;
import org.bouncycastle.asn1.x509.KeyPurposeId;
import org.bouncycastle.asn1.x509.KeyUsage;
import org.bouncycastle.asn1.x509.X509ObjectIdentifiers;
import org.bouncycastle.cert.CertIOException;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;

import java.io.IOException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.Provider;
import java.security.PublicKey;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Arrays;

import static com.intel.bkp.crypto.x509.utils.KeyIdentifierUtils.calculateSubjectKeyIdentifierUsingMethod2FromRfc7093;
import static com.intel.bkp.crypto.x509.utils.KeyIdentifierUtils.createAuthorityKeyIdentifier;
import static com.intel.bkp.crypto.x509.utils.KeyIdentifierUtils.createSubjectKeyIdentifier;

public class X509CertificateBuilder {

    private static final Provider CERT_CONVERTER_PROVIDER = CryptoUtils.getBouncyCastleProvider();
    private static final String DEFAULT_SIGN_ALGORITHM = CryptoConstants.SHA384_WITH_ECDSA;

    private final PublicKey publicKey;
    private final JcaX509v3CertificateBuilder builder;

    public X509CertificateBuilder(X509CertificateBuilderParams dto) {
        this.publicKey = dto.getPublicKey();
        this.builder = dto.getBuilder();
    }

    public X509CertificateBuilder withSubjectKeyIdentifier() throws CertIOException {
        builder.addExtension(Extension.subjectKeyIdentifier, false, createSubjectKeyIdentifier(publicKey));
        return this;
    }

    public X509CertificateBuilder withAuthorityKeyIdentifier(PublicKey issuerPublickey) throws CertIOException {
        final byte[] issuerSki = calculateSubjectKeyIdentifierUsingMethod2FromRfc7093(issuerPublickey);
        final var aki = new AuthorityKeyIdentifier(issuerSki);
        return withAuthorityKeyIdentifier(aki);
    }

    public X509CertificateBuilder withAuthorityKeyIdentifier(X509Certificate issuerCertificate) throws CertIOException,
        CertificateEncodingException, NoSuchAlgorithmException {
        final var aki = createAuthorityKeyIdentifier(issuerCertificate);
        return withAuthorityKeyIdentifier(aki);
    }

    private X509CertificateBuilder withAuthorityKeyIdentifier(AuthorityKeyIdentifier aki) throws CertIOException {
        builder.addExtension(Extension.authorityKeyIdentifier, false, aki);
        return this;
    }

    public X509CertificateBuilder withBasicConstraintsForIssuerCert(int pathLength) throws CertIOException {
        addBasicConstraints(new BasicConstraints(pathLength));
        return this;
    }

    public X509CertificateBuilder withBasicConstraintsForIssuerCertWithUnlimitedPathLength() throws CertIOException {
        addBasicConstraints(new BasicConstraints(true));
        return this;
    }

    public X509CertificateBuilder withBasicConstraintsForLeafCert() throws CertIOException {
        addBasicConstraints(new BasicConstraints(false));
        return this;
    }

    private void addBasicConstraints(BasicConstraints basicConstraints) throws CertIOException {
        builder.addExtension(Extension.basicConstraints, true, basicConstraints);
    }

    public X509CertificateBuilder withKeyUsage(int keyUsage) throws CertIOException {
        KeyUsage usage = new KeyUsage(keyUsage);
        builder.addExtension(Extension.keyUsage, false, usage);
        return this;
    }

    public X509CertificateBuilder withExtendedKeyUsage(String... keyPurposesOids) throws CertIOException {
        final KeyPurposeId[] keyPurposes = Arrays.stream(keyPurposesOids)
            .map(ASN1ObjectIdentifier::new)
            .map(KeyPurposeId::getInstance)
            .toArray(KeyPurposeId[]::new);
        return withExtendedKeyUsage(keyPurposes);
    }

    public X509CertificateBuilder withExtendedKeyUsage(KeyPurposeId... keyPurposes) throws CertIOException {
        builder.addExtension(Extension.extendedKeyUsage, false, new ExtendedKeyUsage(keyPurposes));
        return this;
    }

    public X509CertificateBuilder withCrlDistributionPoints(String crlUrl) throws IOException {
        final var generalName = new GeneralName(GeneralName.uniformResourceIdentifier, crlUrl);
        final var pointName = new DistributionPointName(new GeneralNames(generalName));
        final var points = new DistributionPoint[]{new DistributionPoint(pointName, null, null)};
        builder.addExtension(Extension.cRLDistributionPoints, false, new CRLDistPoint(points));
        return this;
    }

    public X509CertificateBuilder withAuthorityInfoAccess(String issuerCertUrl) throws IOException {
        final var generalName = new GeneralName(GeneralName.uniformResourceIdentifier, issuerCertUrl);
        final var aia = new AuthorityInformationAccess(X509ObjectIdentifiers.crlAccessMethod, generalName);
        builder.addExtension(Extension.authorityInfoAccess, false, aia);
        return this;
    }

    public X509CertificateBuilder withExtension(Extension extension) throws CertIOException {
        builder.addExtension(extension);
        return this;
    }

    public X509Certificate sign(PrivateKey privateKey) throws OperatorCreationException, CertificateException {
        return sign(privateKey, CERT_CONVERTER_PROVIDER, DEFAULT_SIGN_ALGORITHM);
    }

    public X509Certificate sign(PrivateKey privateKey, Provider signProvider, String signAlgorithm)
        throws OperatorCreationException, CertificateException {
        ContentSigner signer = new JcaContentSignerBuilder(signAlgorithm)
            .setProvider(signProvider)
            .build(privateKey);
        return new JcaX509CertificateConverter()
            .setProvider(CERT_CONVERTER_PROVIDER)
            .getCertificate(builder.build(signer));
    }
}

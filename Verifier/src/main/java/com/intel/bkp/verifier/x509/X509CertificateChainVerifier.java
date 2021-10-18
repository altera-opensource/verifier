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

package com.intel.bkp.verifier.x509;

import com.intel.bkp.verifier.exceptions.CertificateChainValidationException;
import lombok.NoArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;

import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.Iterator;
import java.util.List;
import java.util.Optional;
import java.util.Set;
import java.util.stream.Collectors;

import static org.bouncycastle.asn1.x509.Extension.authorityInfoAccess;
import static org.bouncycastle.asn1.x509.Extension.authorityKeyIdentifier;
import static org.bouncycastle.asn1.x509.Extension.basicConstraints;
import static org.bouncycastle.asn1.x509.Extension.cRLDistributionPoints;
import static org.bouncycastle.asn1.x509.Extension.extendedKeyUsage;
import static org.bouncycastle.asn1.x509.Extension.keyUsage;
import static org.bouncycastle.asn1.x509.Extension.subjectKeyIdentifier;

@Slf4j
@NoArgsConstructor
public class X509CertificateChainVerifier {

    public static final Set<String> COMMON_EXTENSION_OIDS = Set.of(basicConstraints, keyUsage, extendedKeyUsage,
        authorityKeyIdentifier, subjectKeyIdentifier, authorityInfoAccess, cRLDistributionPoints).stream()
        .map(ASN1ObjectIdentifier::getId)
        .collect(Collectors.toUnmodifiableSet());
    private static final Optional<Integer> LEAF_BASIC_CONSTRAINTS = Optional.empty();

    private X509CertificateParentVerifier certificateParentVerifier = new X509CertificateParentVerifier();
    private X509CertificateValidityVerifier certificateValidityVerifier = new X509CertificateValidityVerifier();
    private X509CertificateIssuerVerifier certificateIssuerVerifier = new X509CertificateIssuerVerifier();
    private X509CertificateAuthorityKeyIdentifierVerifier certificateAKIVerifier =
        new X509CertificateAuthorityKeyIdentifierVerifier();
    private X509CertificateBasicConstraintsVerifier certificateBasicConstraintsVerifier =
        new X509CertificateBasicConstraintsVerifier();
    private X509CertificateKeyUsageVerifier certificateKeyUsageVerifier = new X509CertificateKeyUsageVerifier();
    private X509CertificateCriticalExtensionsVerifier criticalExtensionsVerifier =
        new X509CertificateCriticalExtensionsVerifier();

    private List<X509Certificate> certificates = new ArrayList<>();
    private Optional<Integer> rootBasicConstraints = Optional.empty();
    private Set<String> knownExtensionOids = new HashSet<>(COMMON_EXTENSION_OIDS);

    X509CertificateChainVerifier(
        X509CertificateParentVerifier certificateParentVerifier,
        X509CertificateValidityVerifier certificateValidityVerifier,
        X509CertificateIssuerVerifier certificateIssuerVerifier,
        X509CertificateAuthorityKeyIdentifierVerifier certificateAKIVerifier,
        X509CertificateBasicConstraintsVerifier certificateBasicConstraintsVerifier,
        X509CertificateKeyUsageVerifier certificateKeyUsageVerifier,
        X509CertificateCriticalExtensionsVerifier criticalExtensionsVerifier) {
        this.certificateParentVerifier = certificateParentVerifier;
        this.certificateValidityVerifier = certificateValidityVerifier;
        this.certificateIssuerVerifier = certificateIssuerVerifier;
        this.certificateAKIVerifier = certificateAKIVerifier;
        this.certificateBasicConstraintsVerifier = certificateBasicConstraintsVerifier;
        this.certificateKeyUsageVerifier = certificateKeyUsageVerifier;
        this.criticalExtensionsVerifier = criticalExtensionsVerifier;
    }

    public X509CertificateChainVerifier certificates(List<X509Certificate> certificates) {
        this.certificates = certificates;
        return this;
    }

    public X509CertificateChainVerifier rootBasicConstraints(int expectedValue) {
        this.rootBasicConstraints = Optional.of(expectedValue);
        return this;
    }

    public X509CertificateChainVerifier knownExtensionOids(Set<String> additionalOids) {
        this.knownExtensionOids.addAll(additionalOids);
        return this;
    }

    public boolean verify() {
        final Iterator<X509Certificate> certificateChainIterator = certificates.iterator();
        return certificates.size() > 1
            && certificateChainIterator.hasNext()
            && verifyChainRecursive(certificateChainIterator.next(), certificateChainIterator,
            LEAF_BASIC_CONSTRAINTS, KeyUsage.DIGITAL_SIGNATURE);
    }

    private boolean verifyChainRecursive(X509Certificate child, Iterator<X509Certificate> chainIterator,
                                         Optional<Integer> expectedBasicConstraints, KeyUsage expectedKeyUsage) {
        try {
            if (chainIterator.hasNext()) {
                final X509Certificate parent = chainIterator.next();
                verifyCertificate(child, parent, expectedBasicConstraints, expectedKeyUsage);
                return verifyChainRecursive(parent, chainIterator, getNext(expectedBasicConstraints),
                    KeyUsage.KEY_CERT_SIGN);
            } else {
                verifyCertificate(child, child, rootBasicConstraints.or(() -> expectedBasicConstraints),
                    KeyUsage.KEY_CERT_SIGN);
                return true;
            }
        } catch (CertificateChainValidationException e) {
            log.error("Certificate chain validation failed.", e);
            return false;
        }
    }

    private Optional<Integer> getNext(Optional<Integer> expectedBasicConstraints) {
        return expectedBasicConstraints
            .map(expected -> expected + 1)
            .or(() -> Optional.of(0));
    }

    private void verifyCertificate(X509Certificate child, X509Certificate parent,
                                   Optional<Integer> childExpectedBasicConstraints, KeyUsage childExpectedKeyUsage)
        throws CertificateChainValidationException {
        certificateValidityVerifier.verify(child);
        certificateParentVerifier.verify(child, parent);
        certificateIssuerVerifier.verify(child, parent);
        certificateAKIVerifier.verify(child, parent);
        certificateKeyUsageVerifier.verify(child, childExpectedKeyUsage);
        if (childExpectedBasicConstraints.isPresent()) {
            certificateBasicConstraintsVerifier.verify(child, childExpectedBasicConstraints.get());
        }
        criticalExtensionsVerifier.verify(child, knownExtensionOids);
    }
}

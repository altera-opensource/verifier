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

package com.intel.bkp.crypto.x509.validation;

import lombok.NoArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;

import java.security.cert.X509Certificate;
import java.util.HashSet;
import java.util.Iterator;
import java.util.LinkedList;
import java.util.List;
import java.util.Optional;
import java.util.Set;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import static org.bouncycastle.asn1.x509.Extension.authorityInfoAccess;
import static org.bouncycastle.asn1.x509.Extension.authorityKeyIdentifier;
import static org.bouncycastle.asn1.x509.Extension.basicConstraints;
import static org.bouncycastle.asn1.x509.Extension.cRLDistributionPoints;
import static org.bouncycastle.asn1.x509.Extension.extendedKeyUsage;
import static org.bouncycastle.asn1.x509.Extension.keyUsage;
import static org.bouncycastle.asn1.x509.Extension.subjectKeyIdentifier;

@Slf4j
@NoArgsConstructor
public class ChainVerifier {

    protected static final Set<String> COMMON_EXTENSION_OIDS = Stream.of(basicConstraints, keyUsage, extendedKeyUsage,
            authorityKeyIdentifier, subjectKeyIdentifier, authorityInfoAccess, cRLDistributionPoints)
            .map(ASN1ObjectIdentifier::getId)
            .collect(Collectors.toUnmodifiableSet());
    private static final Optional<Integer> LEAF_BASIC_CONSTRAINTS = Optional.empty();

    private SignatureVerifier signatureVerifier = new SignatureVerifier();
    private ValidityVerifier validityVerifier = new ValidityVerifier();
    private IssuerVerifier issuerVerifier = new IssuerVerifier();
    private AuthorityKeyIdentifierVerifier akiVerifier = new AuthorityKeyIdentifierVerifier();
    private BasicConstraintsVerifier basicConstraintsVerifier = new BasicConstraintsVerifier();
    private KeyUsageVerifier keyUsageVerifier = new KeyUsageVerifier();
    private CriticalExtensionsVerifier criticalExtensionsVerifier = new CriticalExtensionsVerifier();

    private List<X509Certificate> certificates = new LinkedList<>();
    private Optional<Integer> rootBasicConstraints = Optional.empty();
    private Set<String> knownExtensionOids = new HashSet<>(COMMON_EXTENSION_OIDS);

    public ChainVerifier certificates(List<X509Certificate> certificates) {
        this.certificates = certificates;
        return this;
    }

    public ChainVerifier knownExtensionOids(Set<String> additionalOids) {
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
        if (chainIterator.hasNext()) {
            final X509Certificate parent = chainIterator.next();
            return verifyCertificate(child, parent, expectedBasicConstraints, expectedKeyUsage)
                    && verifyChainRecursive(parent, chainIterator, getNext(expectedBasicConstraints),
                    KeyUsage.KEY_CERT_SIGN);
        } else {
            return verifyCertificate(child, child, rootBasicConstraints.or(() -> expectedBasicConstraints),
                    KeyUsage.KEY_CERT_SIGN);
        }
    }

    private Optional<Integer> getNext(Optional<Integer> expectedBasicConstraints) {
        return expectedBasicConstraints
                .map(expected -> expected + 1)
                .or(() -> Optional.of(0));
    }

    private boolean verifyCertificate(X509Certificate child, X509Certificate parent,
                                      Optional<Integer> childExpectedBasicConstraints, KeyUsage childExpectedKeyUsage) {
        return validityVerifier.verify(child)
                && signatureVerifier.verify(child, parent)
                && issuerVerifier.verify(child, parent)
                && akiVerifier.verify(child, parent)
                && keyUsageVerifier.verify(child, childExpectedKeyUsage)
                && criticalExtensionsVerifier.verify(child, knownExtensionOids)
                && childExpectedBasicConstraints.map(bc -> basicConstraintsVerifier.verify(child, bc)).orElse(true);
    }
}

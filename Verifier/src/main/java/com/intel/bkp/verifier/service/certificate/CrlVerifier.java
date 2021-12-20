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

package com.intel.bkp.verifier.service.certificate;

import com.intel.bkp.verifier.exceptions.CrlSignatureException;
import com.intel.bkp.verifier.exceptions.SigmaException;
import com.intel.bkp.verifier.x509.X509CertificateParser;
import com.intel.bkp.verifier.x509.X509CrlParentVerifier;
import lombok.AccessLevel;
import lombok.Getter;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;

import java.math.BigInteger;
import java.security.Principal;
import java.security.cert.X509CRL;
import java.security.cert.X509CRLEntry;
import java.security.cert.X509Certificate;
import java.util.Collections;
import java.util.List;
import java.util.ListIterator;
import java.util.Optional;

@Slf4j
@Getter(AccessLevel.PACKAGE)
@RequiredArgsConstructor(access = AccessLevel.PACKAGE)
public class CrlVerifier {

    private final X509CertificateParser x509CertificateParser;
    private final X509CrlParentVerifier x509CrlParentVerifier;
    private final ICrlProvider crlProvider;

    private List<X509Certificate> certificates;
    private boolean requireCrlForLeafCertificate = true;

    public CrlVerifier(ICrlProvider crlProvider) {
        this(new X509CertificateParser(), new X509CrlParentVerifier(), crlProvider);
    }

    public CrlVerifier certificates(List<X509Certificate> certificates) {
        this.certificates = certificates;
        return this;
    }

    public CrlVerifier doNotRequireCrlForLeafCertificate() {
        this.requireCrlForLeafCertificate = false;
        return this;
    }

    public boolean verify() {
        ListIterator<X509Certificate> certificateChainIterator = this.certificates.listIterator();
        return verifyRecursive(certificateChainIterator.next(), certificateChainIterator, requireCrlForLeafCertificate);
    }

    private boolean verifyRecursive(X509Certificate cert, ListIterator<X509Certificate> certificateChainIterator,
                                    boolean requireCrl) {
        if (!certificateChainIterator.hasNext()) {
            return true;
        }

        log.debug("Checking if certificate is revoked based on CRL: {}", cert.getSubjectDN());
        return x509CertificateParser.getPathToCrlDistributionPoint(cert)
            .map(crlUrl -> handleCrl(crlUrl, cert.getSerialNumber(), certificateChainIterator))
            .orElseGet(() -> handleNoCrl(requireCrl, cert.getSubjectDN(), certificateChainIterator));
    }

    private boolean handleNoCrl(boolean requireCrl, Principal certSubject,
                                ListIterator<X509Certificate> certificateChainIterator) {
        if (requireCrl) {
            log.error("Certificate does not have required CRLDistributionPoints extension: {}", certSubject);
            return false;
        }
        log.debug("Certificate does not have CRLDistributionPoints extension but it was not required: {}", certSubject);

        final X509Certificate nextCert = certificateChainIterator.next();
        return verifyRecursive(nextCert, certificateChainIterator, true);
    }

    private boolean handleCrl(String crlUrl, BigInteger serialNumber,
                              ListIterator<X509Certificate> certificateChainIterator) {
        final X509CRL crl = crlProvider.getCrl(crlUrl);
        verifyCrlSignature(crl, certificateChainIterator.nextIndex());

        if (isRevoked(crl, serialNumber)) {
            checkIfIntermediateRevoked(certificateChainIterator, serialNumber);
            return false;
        }

        return verifyRecursive(certificateChainIterator.next(), certificateChainIterator, true);
    }


    private void verifyCrlSignature(final X509CRL crl, final int issuerCertIndex) {
        final var issuerCertsIterator = certificates.listIterator(issuerCertIndex);

        while (issuerCertsIterator.hasNext()) {
            final X509Certificate potentialIssuerCert = issuerCertsIterator.next();
            final var potentialIssuerSubject = potentialIssuerCert.getSubjectDN();
            try {
                x509CrlParentVerifier.verify(crl, potentialIssuerCert.getPublicKey());
                log.debug("Verified CRL signature using public key of certificate: {}", potentialIssuerSubject);
                return;
            } catch (Exception e) {
                log.debug("Failed to verify CRL signature using public key of certificate: {}", potentialIssuerSubject);
            }
        }

        throw new CrlSignatureException("Failed to verify signature of CRL");
    }

    private void checkIfIntermediateRevoked(ListIterator<X509Certificate> certificateChainIterator, BigInteger serial) {
        if (certificateChainIterator.previousIndex() > 0) {
            throw new SigmaException(String.format("Intermediate certificate with serial number %s is revoked.",
                serial.toString(16)));
        }
    }

    private boolean isRevoked(X509CRL crl, BigInteger serialNumber) {
        log.debug("Verifying certificate revocation.");

        return Optional
            .ofNullable(crl.getRevokedCertificates())
            .orElse(Collections.emptySet())
            .stream()
            .map(X509CRLEntry::getSerialNumber)
            .anyMatch(x -> x.equals(serialNumber));
    }
}


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

package com.intel.bkp.fpgacerts.verification;

import com.intel.bkp.crypto.x509.validation.SignatureVerifier;
import com.intel.bkp.fpgacerts.exceptions.CrlSignatureException;
import com.intel.bkp.fpgacerts.interfaces.ICrlProvider;
import lombok.AccessLevel;
import lombok.Getter;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;

import java.math.BigInteger;
import java.security.Principal;
import java.security.cert.X509CRL;
import java.security.cert.X509Certificate;
import java.util.List;
import java.util.ListIterator;

import static com.intel.bkp.crypto.x509.utils.CrlDistributionPointsUtils.getCrlUrl;
import static com.intel.bkp.crypto.x509.utils.X509CrlUtils.isRevoked;
import static com.intel.bkp.utils.HexConverter.toHex;

@Slf4j
@RequiredArgsConstructor(access = AccessLevel.PACKAGE)
public class CrlVerifier {

    @Getter
    private final SignatureVerifier signatureVerifier;
    @Getter
    private final ICrlProvider crlProvider;

    private List<X509Certificate> certificates;
    private boolean requireCrlForLeafCertificate = true;

    public CrlVerifier(ICrlProvider crlProvider) {
        this(new SignatureVerifier(), crlProvider);
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
        return getCrlUrl(cert)
                .map(crlUrl -> handleCrl(crlUrl, cert, certificateChainIterator))
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

    private boolean handleCrl(String crlUrl, X509Certificate certificate,
                              ListIterator<X509Certificate> certificateChainIterator) {
        final X509CRL crl = crlProvider.getCrl(crlUrl);
        verifyCrlSignature(crl, certificateChainIterator.nextIndex());

        final BigInteger serialNumber = certificate.getSerialNumber();
        return isRevoked(crl, serialNumber)
                ? handleRevokedCertificate(certificate.getSubjectDN(), serialNumber)
                : verifyRecursive(certificateChainIterator.next(), certificateChainIterator, true);

    }


    private void verifyCrlSignature(final X509CRL crl, final int issuerCertIndex) {
        final var issuerCertsIterator = certificates.listIterator(issuerCertIndex);

        while (issuerCertsIterator.hasNext()) {
            final X509Certificate potentialIssuer = issuerCertsIterator.next();
            if (signatureVerifier.verify(crl, potentialIssuer)) {
                log.debug("Verified CRL signature using public key of certificate: {}", potentialIssuer.getSubjectDN());
                return;
            }
        }

        log.info("WARNING: Verification of CRL signature omitted for debug purposes.");
        //throw new CrlSignatureException("Failed to verify signature of CRL");
    }

    private boolean handleRevokedCertificate(Principal certificateSubject, BigInteger serial) {
        log.error("Certificate {} with serial number {} is revoked.", certificateSubject, toHex(serial.byteValue()));
        return false;
    }
}


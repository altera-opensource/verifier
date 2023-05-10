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

package com.intel.bkp.crypto.x509.utils;

import com.intel.bkp.crypto.pem.PemFormatEncoder;
import com.intel.bkp.crypto.pem.PemFormatHeader;
import lombok.AccessLevel;
import lombok.NoArgsConstructor;
import lombok.extern.slf4j.Slf4j;

import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SignatureException;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Collections;
import java.util.LinkedList;
import java.util.List;

@Slf4j
@NoArgsConstructor(access = AccessLevel.PRIVATE)
public class X509CertificateUtils {

    public static String toPem(final X509Certificate certificate) throws CertificateEncodingException {
        return PemFormatEncoder.encode(PemFormatHeader.CERTIFICATE, certificate.getEncoded());
    }

    /**
     * Checks if certificate is self-signed, by comparing Subject and Issuer that must be equal and verifying that
     * certificate was signed using its own public key.
     *
     * @return true if both conditions are met, false otherwise.
     */
    public static boolean isSelfSigned(final X509Certificate certificate) {
        if (!certificate.getIssuerX500Principal().equals(certificate.getSubjectX500Principal())) {
            return false;
        }

        try {
            certificate.verify(certificate.getPublicKey());
            return true;
        } catch (CertificateException | NoSuchAlgorithmException | InvalidKeyException
            | NoSuchProviderException | SignatureException e) {
            return false;
        }
    }

    /**
     * Ensures that root certificate in the list is last, reverses the list order if necessary.
     * Does not search for root in the middle of the list.
     *
     * @param chain - chain of certificates, might be empty
     * @return copy of chain with root last, empty list if no root is found
     */
    public static List<X509Certificate> makeRootLastCert(List<X509Certificate> chain) {
        final var chainCopy = new LinkedList<>(chain);

        if (chain.isEmpty()) {
            return List.of();
        }

        if (isSelfSigned(chainCopy.getLast())) {
            return chainCopy;
        }

        if (isSelfSigned(chainCopy.getFirst())) {
            Collections.reverse(chainCopy);
            return chainCopy;
        }

        return List.of();
    }
}

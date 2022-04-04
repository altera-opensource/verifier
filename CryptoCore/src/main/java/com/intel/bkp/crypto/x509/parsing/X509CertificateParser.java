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

package com.intel.bkp.crypto.x509.parsing;

import com.intel.bkp.crypto.CryptoUtils;
import com.intel.bkp.crypto.constants.CryptoConstants;
import com.intel.bkp.crypto.exceptions.X509CertificateParsingException;
import lombok.AccessLevel;
import lombok.NoArgsConstructor;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.List;
import java.util.Optional;
import java.util.stream.Collectors;

@NoArgsConstructor(access = AccessLevel.PRIVATE)
public class X509CertificateParser {

    public static X509Certificate pemToX509Certificate(String certInPem) throws X509CertificateParsingException {
        return toX509Certificate(certInPem.getBytes(StandardCharsets.UTF_8));
    }

    public static X509Certificate toX509Certificate(byte[] certBytes) throws X509CertificateParsingException {
        try (InputStream input = new ByteArrayInputStream(certBytes)) {
            return (X509Certificate) getCertificateFactory().generateCertificate(input);
        } catch (CertificateException | IOException e) {
            throw new X509CertificateParsingException("Failed to parse certificate.", e);
        }
    }

    public static Optional<X509Certificate> tryToX509(byte[] certBytes) {
        try {
            return Optional.of(toX509Certificate(certBytes));
        } catch (X509CertificateParsingException e) {
            return Optional.empty();
        }
    }

    public static List<X509Certificate> toX509CertificateChain(byte[] certChainBytes)
        throws X509CertificateParsingException {

        try (InputStream input = new ByteArrayInputStream(certChainBytes)) {
            return getCertificateFactory().generateCertificates(input)
                .stream()
                .map(obj -> (X509Certificate) obj)
                .collect(Collectors.toList());
        } catch (CertificateException | IOException e) {
            throw new X509CertificateParsingException("Failed to parse certificates chain.", e);
        }
    }

    private static CertificateFactory getCertificateFactory() throws CertificateException {
        return CertificateFactory.getInstance(
            CryptoConstants.CERTIFICATE_FACTORY_TYPE,
            CryptoUtils.getBouncyCastleProvider());
    }
}

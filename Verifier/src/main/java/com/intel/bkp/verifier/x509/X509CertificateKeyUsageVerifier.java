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

import java.security.cert.X509Certificate;
import java.util.Optional;

public class X509CertificateKeyUsageVerifier {

    public void verify(final X509Certificate certificate, KeyUsage keyUsage)
        throws CertificateChainValidationException {

        if (!containsKeyUsage(certificate, keyUsage)) {
            handleIncorrectKeyUsage(certificate);
        }
    }

    private boolean containsKeyUsage(final X509Certificate certificate, final KeyUsage keyUsage) {
        final int index = keyUsage.getBitIndex();
        return Optional.ofNullable(certificate.getKeyUsage())
            .filter(usages -> index < usages.length)
            .map(usages -> usages[index])
            .orElse(false);
    }

    private void handleIncorrectKeyUsage(final X509Certificate certificate) throws CertificateChainValidationException {
        final var errorMessage = String.format(
            "Certificate does not have required KeyUsage: %s.", certificate.getSubjectDN());
        throw new CertificateChainValidationException(errorMessage);
    }
}

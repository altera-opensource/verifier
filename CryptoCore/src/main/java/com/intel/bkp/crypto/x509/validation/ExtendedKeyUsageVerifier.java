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

package com.intel.bkp.crypto.x509.validation;

import lombok.extern.slf4j.Slf4j;
import org.bouncycastle.asn1.x509.KeyPurposeId;

import java.security.cert.CertificateParsingException;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.Optional;

@Slf4j
public class ExtendedKeyUsageVerifier {

    public static final String KEY_PURPOSE_CODE_SIGNING = KeyPurposeId.id_kp_codeSigning.getId();

    private X509Certificate certificate;

    public ExtendedKeyUsageVerifier certificate(X509Certificate certificate) {
        this.certificate = certificate;
        return this;
    }

    public boolean verify(String... keyPurposes) {
        final String subjectDN = certificate.getSubjectDN().getName();
        try {
            final boolean valid = Optional.ofNullable(certificate.getExtendedKeyUsage())
                .map(c -> Arrays.stream(keyPurposes).anyMatch(c::contains))
                .orElse(false);

            if (!valid) {
                log.error("Certificate has invalid key usage: {}", subjectDN);
            }

            return valid;
        } catch (CertificateParsingException e) {
            log.error("Failed to parse key usage in certificate: {}.", subjectDN, e);
            return false;
        }
    }
}

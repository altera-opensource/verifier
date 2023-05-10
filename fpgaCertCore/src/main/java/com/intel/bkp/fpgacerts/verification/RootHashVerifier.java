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

package com.intel.bkp.fpgacerts.verification;

import com.intel.bkp.crypto.CryptoUtils;
import com.intel.bkp.fpgacerts.exceptions.X509Exception;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.lang3.StringUtils;

import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.util.Locale;

@Slf4j
public class RootHashVerifier {

    public boolean verifyRootHash(X509Certificate rootCert, String trustedRootHash) {
        if (StringUtils.isBlank(trustedRootHash)) {
            log.warn("Skipping root hash verification - trusted root hash was not provided.");
            return true;
        }

        final String rootHash = getCertificateFingerprint(rootCert);
        final boolean isRootTrusted = rootHash.equalsIgnoreCase(trustedRootHash);
        if (!isRootTrusted) {
            log.debug("Root fingerprints do not match.\nExpected: {}\nActual:   {}",
                trustedRootHash.toUpperCase(Locale.ROOT), rootHash.toUpperCase(Locale.ROOT));
        }

        return isRootTrusted;
    }

    private String getCertificateFingerprint(X509Certificate certificate) {
        final byte[] certificateBytes = getCertificateContent(certificate);
        return CryptoUtils.generateSha256Fingerprint(certificateBytes);
    }

    private byte[] getCertificateContent(X509Certificate certificate) {
        try {
            return certificate.getEncoded();
        } catch (CertificateEncodingException e) {
            throw new X509Exception("Failed to get bytes from X509 certificate.", e);
        }
    }
}

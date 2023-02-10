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
import org.bouncycastle.asn1.x509.Extension;

import java.security.cert.X509Certificate;

import static com.intel.bkp.crypto.x509.utils.X509ExtensionUtils.containsExtension;


@Slf4j
public class BasicConstraintsVerifier {

    public static final int CA_FALSE = -1;
    public static final int CA_TRUE_PATHLENGTH_NONE = Integer.MAX_VALUE;

    public boolean verify(final X509Certificate certificate, int expectedValue) {
        if (!containsExtension(certificate, Extension.basicConstraints)) {
            logMissingBasicConstraints(certificate);
            return false;
        }

        final int actual = certificate.getBasicConstraints();
        final boolean valid = actual >= expectedValue;
        if (!valid) {
            logUnexpectedBasicConstraintsValue(certificate, expectedValue, actual);
        }
        return valid;
    }

    private void logMissingBasicConstraints(X509Certificate certificate) {
        log.error("Certificate is missing BasicConstraints extension: {}.",
            certificate.getSubjectX500Principal());
    }

    private void logUnexpectedBasicConstraintsValue(X509Certificate certificate, int expected, int actual) {
        log.error("Certificate has incorrect BasicConstraints value: {}\nExpected: {}\nActual: {}",
            certificate.getSubjectX500Principal(), basicConstraintsValueToString(expected),
            basicConstraintsValueToString(actual));
    }

    private String basicConstraintsValueToString(int value) {
        if (CA_FALSE == value) {
            return "CA=false";
        } else if (CA_TRUE_PATHLENGTH_NONE == value) {
            return "CA=true, pathlength=None";
        } else if (value >= 0) {
            return String.format("CA=true, pathlength=%d", value);
        } else {
            return String.format("Unrecognized basic constraints value: %d", value);
        }
    }
}

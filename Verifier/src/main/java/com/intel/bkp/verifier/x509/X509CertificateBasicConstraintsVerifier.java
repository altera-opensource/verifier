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
import lombok.extern.slf4j.Slf4j;
import org.bouncycastle.asn1.x509.Extension;

import java.security.cert.X509Certificate;

import static com.intel.bkp.ext.core.certificate.X509CertificateUtils.containsExtension;

@Slf4j
public class X509CertificateBasicConstraintsVerifier {

    public static int CA_FALSE = -1;
    public static int CA_TRUE_PATHLENGTH_NONE = Integer.MAX_VALUE;

    public void verify(final X509Certificate certificate, int expectedValue)
        throws CertificateChainValidationException {

        if (!containsExtension(certificate, Extension.basicConstraints)) {
            handleMissingBasicConstraints(certificate);
        }

        final int actual = certificate.getBasicConstraints();
        if (expectedValue > actual) {
            handleUnexpectedBasicConstraintsValue(certificate, expectedValue, actual);
        }
    }

    private void handleMissingBasicConstraints(X509Certificate certificate)
        throws CertificateChainValidationException {
        final var errorMessage = String.format(
            "Certificate is missing BasicConstraints extension: %s.",
            certificate.getSubjectDN());
        throw new CertificateChainValidationException(errorMessage);
    }

    private void handleUnexpectedBasicConstraintsValue(X509Certificate certificate, int expected, int actual)
        throws CertificateChainValidationException {
        final var errorMessage = String.format(
            "Certificate has incorrect BasicConstraints value: %s\nExpected: %s\nActual: %s",
            certificate.getSubjectDN(), basicConstraintsValueToString(expected), basicConstraintsValueToString(actual));
        throw new CertificateChainValidationException(errorMessage);
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

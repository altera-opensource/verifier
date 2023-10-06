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

package com.intel.bkp.fpgacerts.utils;

import com.intel.bkp.crypto.exceptions.X509CertificateParsingException;
import com.intel.bkp.crypto.x509.utils.AuthorityInformationAccessUtils;
import com.intel.bkp.fpgacerts.exceptions.X509Exception;
import lombok.AccessLevel;
import lombok.NoArgsConstructor;
import lombok.extern.slf4j.Slf4j;

import java.security.cert.X509Certificate;

import static com.intel.bkp.crypto.x509.parsing.X509CertificateParser.toX509Certificate;

@Slf4j
@NoArgsConstructor(access = AccessLevel.PRIVATE)
public class X509UtilsWrapper {

    public static String getIssuerCertUrl(X509Certificate certificate) {
        return AuthorityInformationAccessUtils.getIssuerCertUrl(certificate)
                .orElseThrow(() -> new X509Exception("No AuthorityInformationAccess extension in certificate."));
    }

    public static X509Certificate toX509(byte[] certificate) {
        try {
            return toX509Certificate(certificate);
        } catch (X509CertificateParsingException e) {
            throw new X509Exception("Failed to parse X.509 certificate.", e);
        }
    }
}

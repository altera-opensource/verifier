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

package com.intel.bkp.crypto.x509.utils;

import org.apache.commons.lang3.StringUtils;
import org.bouncycastle.asn1.x509.AccessDescription;
import org.bouncycastle.asn1.x509.AuthorityInformationAccess;
import org.bouncycastle.asn1.x509.Extension;

import java.security.cert.X509Certificate;
import java.util.Optional;
import java.util.stream.Stream;

import static com.intel.bkp.crypto.x509.utils.X509CertificateUtils.getExtensionBytes;

public class AuthorityInformationAccessUtils {

    public static Optional<String> getIssuerCertUrl(X509Certificate certificate) {
        return extractAccessDescriptions(certificate)
                .map(AuthorityInformationAccessUtils::getLocationName)
                .filter(StringUtils::isNotBlank)
                .findFirst();
    }

    private static Stream<AccessDescription> extractAccessDescriptions(X509Certificate certificate) {
        return getExtensionBytes(certificate, Extension.authorityInfoAccess)
                .map(AuthorityInformationAccess::getInstance)
                .map(AuthorityInformationAccess::getAccessDescriptions)
                .stream()
                .flatMap(Stream::of);
    }

    private static String getLocationName(AccessDescription accessDescription) {
        return accessDescription.getAccessLocation().getName().toString();
    }
}

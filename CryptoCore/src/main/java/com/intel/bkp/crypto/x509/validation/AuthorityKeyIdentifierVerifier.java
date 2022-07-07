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

import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.Optional;

import static com.intel.bkp.crypto.x509.utils.KeyIdentifierUtils.getAuthorityKeyIdentifier;
import static com.intel.bkp.crypto.x509.utils.KeyIdentifierUtils.getSubjectKeyIdentifier;


@Slf4j
public class AuthorityKeyIdentifierVerifier {

    public boolean verify(final X509Certificate child, final X509Certificate parent) {
        final Optional<byte[]> childAKI = Optional.ofNullable(getAuthorityKeyIdentifier(child));
        final boolean valid = childAKI.isEmpty() || childAKIMatchesParentSKI(childAKI.get(), parent);
        if (!valid) {
            logMismatchedAKI(child);
        }
        return valid;
    }

    private boolean childAKIMatchesParentSKI(byte[] childAKI, X509Certificate parent) {
        final byte[] parentSKI = getSubjectKeyIdentifier(parent);
        return Arrays.equals(childAKI, parentSKI);
    }

    private void logMismatchedAKI(final X509Certificate child) {
        log.error("Certificate has AKI that does not match SKI of parent certificate: {}.",
            child.getSubjectX500Principal());
    }
}

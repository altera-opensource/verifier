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

package com.intel.bkp.verifier.model.dice;

import com.intel.bkp.ext.core.certificate.X509CertificateUtils;
import com.intel.bkp.verifier.exceptions.InternalLibraryException;
import com.intel.bkp.verifier.interfaces.ICertificateParser;

import java.security.Principal;
import java.security.cert.X509Certificate;
import java.util.Optional;
import java.util.function.Function;

public abstract class DiceParamsParserBase implements ICertificateParser {

    private static final int EXPECTED_FIELDS_COUNT = 5;
    private static final String FIELD_DELIMITER = ":";

    @Override
    public abstract void parse(X509Certificate certificate);

    protected final String[] parsePrincipalField(X509Certificate certificate,
        Function<X509Certificate, Principal> mappingFunc) {

        final String[] strings = Optional.ofNullable(certificate)
            .map(mappingFunc)
            .map(Principal::getName)
            .map(name -> name.split(FIELD_DELIMITER))
            .orElse(new String[] {});

        if (strings.length < EXPECTED_FIELDS_COUNT) {
            throw new InternalLibraryException(String.format(
                "Received certificate does not contain valid fields: %s", String.join(":", strings))
            );
        }

        return strings;
    }

    protected final byte[] parseAuthorityKeyIdentifier(X509Certificate certificate) {
        return Optional.ofNullable(certificate)
            .map(X509CertificateUtils::getAuthorityKeyIdentifier)
            .orElse(new byte[] {});
    }
}

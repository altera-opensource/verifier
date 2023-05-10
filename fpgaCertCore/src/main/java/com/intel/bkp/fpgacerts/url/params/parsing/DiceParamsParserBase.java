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

package com.intel.bkp.fpgacerts.url.params.parsing;

import com.intel.bkp.fpgacerts.dice.subject.DiceCertificateSubject;
import com.intel.bkp.fpgacerts.exceptions.X509Exception;
import com.intel.bkp.fpgacerts.url.params.DiceParams;
import com.intel.bkp.utils.Base64Url;
import com.intel.bkp.utils.ByteBufferSafe;
import lombok.NonNull;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;

import java.security.Principal;
import java.security.cert.X509Certificate;
import java.util.Optional;

@Slf4j
@RequiredArgsConstructor
public abstract class DiceParamsParserBase<T extends DiceParams> {

    private final ICertificateMapper certificateMapper;
    private final KeyIdentifierProvider keyIdentifierProvider = new KeyIdentifierProvider();
    private final DomainNameParser domainNameParser = new DomainNameParser();


    protected abstract T getDiceParams(String ski, DiceCertificateSubject subject);

    public final T parse(@NonNull X509Certificate certificate) {
        log.debug("Parsing Dice URL params from certificate: {}", certificate.getSubjectX500Principal());

        final String ski = keyIdentifierProvider.getKeyIdentifierInBase64Url(certificate);
        final DiceCertificateSubject subject = domainNameParser.parse(certificate);
        final T diceParams = getDiceParams(ski, subject);

        log.debug("Parsed from certificate: {}", diceParams);

        return diceParams;
    }

    private class KeyIdentifierProvider {

        private static final int SKI_BYTES_FOR_URL = 20;

        public String getKeyIdentifierInBase64Url(X509Certificate certificate) {
            final byte[] keyIdentifier = getKeyIdentifierBytes(certificate);
            byte[] shortenKeyIdentifier = new byte[SKI_BYTES_FOR_URL];
            ByteBufferSafe.wrap(keyIdentifier).get(shortenKeyIdentifier);
            return Base64Url.encodeWithoutPadding(shortenKeyIdentifier);
        }

        private byte[] getKeyIdentifierBytes(X509Certificate certificate) {
            return Optional.ofNullable(certificate)
                .map(certificateMapper.getKeyIdentifierMappingFunc())
                .orElseThrow(() ->
                    new X509Exception("Certificate does not contain required key identifier extension."));
        }
    }

    private class DomainNameParser {

        DiceCertificateSubject parse(X509Certificate certificate) {
            final String domainName = Optional.ofNullable(certificate)
                .map(certificateMapper.getDomainNameMappingFunc())
                .map(Principal::getName)
                .orElse("");

            return DiceCertificateSubject.parse(domainName);
        }
    }
}

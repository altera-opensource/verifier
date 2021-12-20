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

import com.intel.bkp.ext.utils.Base64Url;
import com.intel.bkp.ext.utils.ByteBufferSafe;
import com.intel.bkp.verifier.exceptions.X509ParsingException;

import java.security.cert.X509Certificate;
import java.util.Optional;
import java.util.function.Function;

public class KeyIdentifierProvider {

    private static final int SKI_BYTES_FOR_URL = 20;

    public String getKeyIdentifierInBase64Url(X509Certificate certificate,
                                              Function<X509Certificate, byte[]> mappingFunc) {

        final byte[] keyIdentifier = getKeyIdentifierBytes(certificate, mappingFunc);
        byte[] shortenKeyIdentifier = new byte[SKI_BYTES_FOR_URL];
        ByteBufferSafe.wrap(keyIdentifier).get(shortenKeyIdentifier);
        return Base64Url.encodeWithoutPadding(shortenKeyIdentifier);
    }

    private byte[] getKeyIdentifierBytes(X509Certificate certificate, Function<X509Certificate, byte[]> mappingFunc) {
        return Optional.ofNullable(certificate)
            .map(mappingFunc)
            .orElseThrow(() ->
                new X509ParsingException("Certificate does not contain required key identifier extension."));
    }
}

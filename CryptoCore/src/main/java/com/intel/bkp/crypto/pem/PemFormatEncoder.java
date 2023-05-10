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

package com.intel.bkp.crypto.pem;

import lombok.AccessLevel;
import lombok.NoArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.bouncycastle.util.io.pem.PemObject;
import org.bouncycastle.util.io.pem.PemReader;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.util.Base64;
import java.util.Optional;

import static java.nio.charset.StandardCharsets.UTF_8;

@Slf4j
@NoArgsConstructor(access = AccessLevel.PRIVATE)
public class PemFormatEncoder {

    private static final int BLOCK_LENGTH = 64;

    public static String encode(PemFormatHeader header, byte[] bytes) {
        return encode(header, bytes, System.lineSeparator());
    }

    public static String encode(PemFormatHeader header, byte[] bytes, String lineSeparator) {
        final StringBuilder stringBuilder = new StringBuilder();
        stringBuilder.append(header.getBegin());
        stringBuilder.append(lineSeparator);
        stringBuilder.append(Base64.getMimeEncoder(BLOCK_LENGTH, lineSeparator.getBytes())
            .encodeToString(bytes));
        stringBuilder.append(lineSeparator);
        stringBuilder.append(header.getEnd());
        return stringBuilder.toString();
    }

    public static byte[] decode(byte[] pubKeyPem) throws IOException {
        try (InputStreamReader reader = new InputStreamReader(new ByteArrayInputStream(pubKeyPem), UTF_8);
             PemReader pemReader = new PemReader(reader)) {
            return getReadPemObject(pemReader)
                .map(PemObject::getContent)
                .orElseThrow(() -> new IllegalArgumentException("Provided public key is not PEM format."));
        }
    }

    private static Optional<PemObject> getReadPemObject(PemReader pemReader) {
        try {
            return Optional.ofNullable(pemReader.readPemObject());
        } catch (Exception e) {
            log.error("Failed to read PEM data: {}", e.getMessage());
            log.debug("Stacktrace: ", e);
            return Optional.empty();
        }
    }
}

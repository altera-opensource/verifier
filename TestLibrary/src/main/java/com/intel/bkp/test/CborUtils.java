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

package com.intel.bkp.test;

import com.intel.bkp.fpgacerts.cbor.exception.CborParserException;
import com.upokecenter.cbor.CBORObject;
import lombok.AccessLevel;
import lombok.NoArgsConstructor;

import java.io.ByteArrayInputStream;
import java.io.InputStream;

import static com.intel.bkp.utils.HexConverter.toHex;
import static java.lang.System.lineSeparator;

/**
 * This utility class helps to convert cbor data similarly to <a href="https://cbor.me">cbor.me</a>.
 */
@NoArgsConstructor(access = AccessLevel.PRIVATE)
public class CborUtils {

    public static String describe(byte[] cborData) {
        try (InputStream stream = new ByteArrayInputStream(cborData)) {
            final var cbor = CBORObject.Read(stream);
            if (cbor == null) {
                return "";
            }
            return describe(cbor);
        } catch (Exception e) {
            throw new CborParserException("Failed to parse cbor binary data", e);
        }
    }

    public static String describe(CBORObject cbor) {
        return new StringBuilder("CBOR")
            .append(lineSeparator())
            .append("Raw:").append(lineSeparator()).append(cbor)
            .append(lineSeparator()).append("Json:").append(lineSeparator()).append(cbor.ToJSONString())
            .append(lineSeparator()).append("Bytes:").append(lineSeparator()).append(toHex(cbor.EncodeToBytes()))
            .toString();
    }
}

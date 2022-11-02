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

package com.intel.bkp.verifier.transport.tcp;

import com.intel.bkp.verifier.utils.RegexUtils;
import lombok.Getter;
import lombok.experimental.SuperBuilder;
import org.apache.commons.lang3.StringUtils;

import java.util.Optional;

@Getter
@SuperBuilder
public class TcpConfig {

    private static final String ERROR_HOST = "Error parsing host in transportId";
    private static final String ERROR_PORT = "Error parsing port number in transportId";
    private static final String ERROR_PORT_NULL = "\"port\" parameter in transportId must not be null.";
    private static final String PATTERN_HOST = "host:([^;]*)";
    private static final String PATTERN_PORT = "port:([^;]*)";

    private String host;
    private Integer port;

    public TcpConfig(String transportId) {
        final String transportIdFormatted = removeWhitespaces(transportId);

        host = parseString(transportIdFormatted, PATTERN_HOST, ERROR_HOST);
        port = Optional.ofNullable(parseInteger(transportIdFormatted, PATTERN_PORT, ERROR_PORT))
            .orElseThrow(() -> new IllegalArgumentException(ERROR_PORT_NULL));
    }

    protected static String removeWhitespaces(String str) {
        return str.replaceAll("\\s+", "");
    }

    protected static String parseString(String str, String pattern, String errorMessage) {
        final String parsed = RegexUtils.getByPattern(str, pattern);
        if (StringUtils.isBlank(parsed)) {
            throw new IllegalArgumentException(errorMessage);
        }
        return parsed;
    }

    protected static Integer parseInteger(String str, String pattern, String errorMessage) {
        try {
            return Optional.of(RegexUtils.getByPattern(str, pattern))
                .filter(StringUtils::isNotBlank)
                .map(Integer::parseInt)
                .orElse(null);
        } catch (NumberFormatException e) {
            throw new IllegalArgumentException(errorMessage, e);
        }
    }
}

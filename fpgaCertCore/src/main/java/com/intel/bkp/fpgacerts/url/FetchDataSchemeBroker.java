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

package com.intel.bkp.fpgacerts.url;

import com.intel.bkp.fpgacerts.dp.DistributionPointConnector;
import com.intel.bkp.fpgacerts.exceptions.DataPathException;
import com.intel.bkp.fpgacerts.utils.LocalFileLoader;
import org.apache.commons.lang3.StringUtils;

import java.net.URI;
import java.net.URISyntaxException;
import java.util.Optional;

public class FetchDataSchemeBroker {

    private static final String HTTPS_SCHEME = "https";
    private static final String HTTP_SCHEME = "http";
    private static final String FILE_SCHEME = "file";

    public static Optional<byte[]> fetchData(String url, DistributionPointConnector dpConnector) {
        final URI uri = toUri(url);
        return switch (extractScheme(uri)) {
            case HTTPS_SCHEME, HTTP_SCHEME -> dpConnector.tryGetBytes(url);
            case FILE_SCHEME -> LocalFileLoader.load(uri);
            default -> Optional.empty();
        };
    }

    private static String extractScheme(URI uri) {
        return Optional.ofNullable(uri.getScheme()).map(String::toLowerCase).orElse("");
    }

    private static URI toUri(String url) {
        if (StringUtils.isBlank(url)) {
            throw new DataPathException("Unable to parse empty url");
        }
        try {
            return new URI(url);
        } catch (URISyntaxException e) {
            throw new DataPathException("Unable to parse url: %s".formatted(url));
        }
    }
}

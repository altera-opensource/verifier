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

package com.intel.bkp.verifier.dp;

import com.intel.bkp.verifier.exceptions.ConnectionException;
import com.intel.bkp.verifier.model.Proxy;
import lombok.extern.slf4j.Slf4j;

import java.io.IOException;
import java.net.HttpURLConnection;
import java.net.ProxySelector;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.util.Optional;

@Slf4j
public class DistributionPointConnector {

    private final ProxySelector proxy;

    public DistributionPointConnector(Proxy proxy) {
        this.proxy = ProxyCallbackFactory.get(proxy.getHost(), proxy.getPort()).get();
    }

    public String getString(String url) {
        return getHttpResponseBody(url, HttpResponse.BodyHandlers.ofString());
    }

    public byte[] getBytes(String url) {
        return getHttpResponseBody(url, HttpResponse.BodyHandlers.ofByteArray());
    }

    public Optional<byte[]> tryGetBytes(String url) {
        Optional<byte[]> responseBody = Optional.empty();
        final HttpResponse<byte[]> response;
        try {
            response = tryGetHttpResponse(url, HttpResponse.BodyHandlers.ofByteArray());
            if (HttpURLConnection.HTTP_OK == response.statusCode()) {
                responseBody = Optional.of(response.body());
            }
        } catch (IOException | InterruptedException e) {
            log.warn("Failed to get http response.", e);
        }
        return responseBody;
    }

    private <T> T getHttpResponseBody(String url, HttpResponse.BodyHandler<T> bodyHandler) {
        try {
            final HttpResponse<T> response = tryGetHttpResponse(url, bodyHandler);
            if (HttpURLConnection.HTTP_OK == response.statusCode()) {
                return response.body();
            }
            throw new ConnectionException("Failed to make request to distribution point. Received wrong status code:"
                + response.statusCode());
        } catch (IOException | InterruptedException e) {
            throw new ConnectionException("Failed to make request to distribution point.", e);
        }
    }

    private <T> HttpResponse<T> tryGetHttpResponse(String url, HttpResponse.BodyHandler<T> bodyHandler)
        throws IOException, InterruptedException {

        return HttpClient.newBuilder()
            .proxy(proxy)
            .build()
            .send(getHttpRequest(url), bodyHandler);
    }

    private HttpRequest getHttpRequest(String url) {
        log.info("Performing request to: {}", url);
        return HttpRequest.newBuilder(URI.create(url))
            .GET()
            .build();
    }
}

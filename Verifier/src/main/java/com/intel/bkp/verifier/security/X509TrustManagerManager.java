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

package com.intel.bkp.verifier.security;

import com.intel.bkp.core.properties.TrustStore;
import com.intel.bkp.fpgacerts.dp.AcceptAllTrustManager;
import com.intel.bkp.verifier.exceptions.X509TrustManagerRuntimeException;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;

import javax.net.ssl.TrustManager;
import javax.net.ssl.TrustManagerFactory;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;

@RequiredArgsConstructor
@Slf4j
public class X509TrustManagerManager {

    private final TrustStore trustStoreParams;

    public TrustManager[] getTrustManagers() {
        if (checkIfTrustStoreExist()) {
            try {
                return loadTrustManager();
            } catch (NoSuchAlgorithmException | KeyStoreException e) {
                throw new X509TrustManagerRuntimeException("Failed to load trust store", e);
            }
        } else {
            log.warn("**WARNING** Skipped SSL verification - using accept all strategy");
            return new TrustManager[]{AcceptAllTrustManager.instance()};
        }
    }

    private TrustManager[] loadTrustManager() throws NoSuchAlgorithmException, KeyStoreException {
        final var tmf = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
        final var keyStore = KeyStore.getInstance(trustStoreParams.getType());
        log.debug("Opening trust store file....");
        try (InputStream inputStream = new FileInputStream(trustStoreParams.getLocation())) {
            keyStore.load(inputStream, trustStoreParams.getPassword().toCharArray());
        } catch (NoSuchAlgorithmException | IOException e) {
            throw new X509TrustManagerRuntimeException("Failed to load trust store", e);
        } catch (CertificateException e) {
            throw new X509TrustManagerRuntimeException("Failed to load certificate from trust store", e);
        }

        tmf.init(keyStore);
        return tmf.getTrustManagers();
    }

    private boolean checkIfTrustStoreExist() {
        final var trustStorePath = trustStoreParams.getLocation();
        if (trustStorePath == null || trustStorePath.isEmpty()) {
            log.info("Trust store filename for was not specified in app properties.");
            return false;
        }

        final var file = new File(trustStorePath);
        if (!file.exists() || file.isDirectory()) {
            log.info("Trust store file does not exist.");
            return false;
        } else {
            return true;
        }
    }
}

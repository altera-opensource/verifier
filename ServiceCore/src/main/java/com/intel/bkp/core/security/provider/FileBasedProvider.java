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

package com.intel.bkp.core.security.provider;

import com.intel.bkp.core.exceptions.JceSecurityProviderException;
import com.intel.bkp.core.security.IKeystoreManager;
import org.apache.commons.lang3.SystemUtils;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.nio.file.attribute.PosixFilePermission;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;
import java.util.Optional;
import java.util.Set;
import java.util.stream.Collectors;
import java.util.stream.Stream;

public class FileBasedProvider implements IKeystoreManager {

    @Override
    public void load(KeyStore keyStore, String inputStreamParam, String password)
        throws KeyStoreException, IOException, NoSuchAlgorithmException, CertificateException {
        if (inputStreamParam == null || inputStreamParam.length() == 0) {
            throw new JceSecurityProviderException(
                "Keystore filename for '" + this.getClass().getName() + "' was not specified in app properties.");
        }

        File file = new File(inputStreamParam);
        if (!file.exists() || file.isDirectory()) {
            keyStore.load(null, null);
            storeInternal(keyStore, inputStreamParam, password);
            if (!SystemUtils.IS_OS_WINDOWS) {
                setOnlyOwnerPermissionsOnFile(inputStreamParam);
            }
        } else {
            try (FileInputStream inputStream = new FileInputStream(inputStreamParam)) {
                keyStore.load(inputStream, Optional.ofNullable(password).orElse("").toCharArray());
            }
        }
    }

    @Override
    public void store(KeyStore keyStore, String inputStreamParam, String password)
        throws KeyStoreException, IOException, NoSuchAlgorithmException, CertificateException {
        storeInternal(keyStore, inputStreamParam, password);
    }

    private void storeInternal(KeyStore keyStore, String inputStreamParam, String password)
        throws KeyStoreException, IOException, NoSuchAlgorithmException, CertificateException {
        try (FileOutputStream fileOutputStream = new FileOutputStream(inputStreamParam)) {
            keyStore.store(fileOutputStream, Optional.ofNullable(password).orElse("").toCharArray());
        }
    }

    private void setOnlyOwnerPermissionsOnFile(String path) throws IOException {
        Set<PosixFilePermission> permissions = Stream
            .of(PosixFilePermission.OWNER_READ, PosixFilePermission.OWNER_WRITE)
            .collect(Collectors.toSet());
        Files.setPosixFilePermissions(Paths.get(path), permissions);
    }
}

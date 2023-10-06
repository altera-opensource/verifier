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

import com.intel.bkp.test.enumeration.ResourceDir;
import com.intel.bkp.test.interfaces.IResourceDir;
import com.intel.bkp.utils.PathUtils;
import lombok.SneakyThrows;
import org.apache.commons.io.IOUtils;

import java.io.FileInputStream;
import java.io.InputStream;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.security.cert.X509CRL;
import java.security.cert.X509Certificate;

import static com.intel.bkp.crypto.x509.parsing.X509CertificateParser.toX509Certificate;
import static com.intel.bkp.crypto.x509.parsing.X509CrlParser.toX509Crl;

public class FileUtils {

    public static final String TEST_FOLDER = "testfiles/";

    @SneakyThrows
    public static byte[] loadBinary(IResourceDir callback, String fileName) {
        final InputStream stream = FileUtils.class.getResourceAsStream(callback.buildPath(fileName));
        assert stream != null;
        return IOUtils.toByteArray(stream);
    }

    @SneakyThrows
    public static String loadFile(IResourceDir callback, String fileName) {
        final InputStream stream = FileUtils.class.getResourceAsStream(callback.buildPath(fileName));
        assert stream != null;
        return IOUtils.toString(stream, StandardCharsets.UTF_8).trim();
    }

    public static X509Certificate loadCertificate(String filename) throws Exception {
        final byte[] fileContent = loadBinary(ResourceDir.CERTS, filename);
        return toX509Certificate(fileContent);
    }

    @SneakyThrows
    public static X509CRL loadCrl(String filename) {
        final byte[] fileContent = loadBinary(ResourceDir.CERTS, filename);
        return toX509Crl(fileContent);
    }

    public static String loadKey(String filename) {
        String key = loadFile(ResourceDir.KEYS, filename);

        if (key.endsWith("\n")) {
            key = key.substring(0, key.length() - 1);
        }

        return key;
    }

    /**
     * Loads file from current module resource not TestLibrary resources.
     *
     * @param pathToFolderInResources Module related resource path
     * @param filename File name in resources
     *
     * @return file content
     *
     * @throws Exception File not exists
     */
    public static byte[] readFromResources(String pathToFolderInResources, String filename) throws Exception {
        final String fullFilePath = PathUtils.buildPath(pathToFolderInResources, filename);
        final URL fileUrl = Thread.currentThread().getContextClassLoader().getResource(fullFilePath);

        assert fileUrl != null : "File in resources is not found: %s".formatted(fullFilePath);

        try (FileInputStream fis = new FileInputStream(fileUrl.getPath())) {
            int available = fis.available();
            if (available > 0) {
                byte[] dst = new byte[available];
                fis.read(dst);
                return dst;
            } else {
                throw new RuntimeException("No test data available.");
            }
        }
    }

    public static String getPathFromResources(String pathToFolderInResources, String filename) {
        final String fullFilePath = PathUtils.buildPath(pathToFolderInResources, filename);
        final URL fileUrl = Thread.currentThread().getContextClassLoader().getResource(fullFilePath);

        assert fileUrl != null : "File in resources is not found: %s".formatted(fullFilePath);

        return fileUrl.getPath();
    }

    public static String readFromResourcesAsString(String pathToFolderInResources, String filename) throws Exception {
        return new String(readFromResources(pathToFolderInResources, filename)).trim();
    }
}

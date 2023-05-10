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

package com.intel.bkp.fpgacerts;

import java.io.FileInputStream;
import java.net.URL;
import java.security.cert.X509CRL;
import java.security.cert.X509Certificate;

import static com.intel.bkp.crypto.x509.parsing.X509CertificateParser.toX509Certificate;
import static com.intel.bkp.crypto.x509.parsing.X509CrlParser.toX509Crl;

public class Utils {

    public static X509Certificate readCertificate(String folder, String filename) throws Exception {
        return toX509Certificate(readFromResources(folder, filename));
    }

    public static X509CRL readCrl(String folder, String filename) throws Exception {
        return toX509Crl(readFromResources(folder, filename));
    }

    public static byte[] readFromResources(String pathToFolderInResources, String filename) throws Exception {
        URL fileUrl = Thread.currentThread().getContextClassLoader()
                .getResource(pathToFolderInResources + filename);

        assert fileUrl != null;

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
}

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

package com.intel.bkp.crypto.x509.validation;

import lombok.extern.slf4j.Slf4j;

import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SignatureException;
import java.security.cert.CRLException;
import java.security.cert.CertificateException;
import java.security.cert.X509CRL;
import java.security.cert.X509Certificate;

@Slf4j
public class SignatureVerifier {

    public boolean verify(X509Certificate child, X509Certificate parent) {
        try {
            log.debug("Verifying certificate {} with public key of {}",
                child.getSubjectX500Principal(), parent.getSubjectX500Principal());
            child.verify(parent.getPublicKey());
            return true;
        } catch (CertificateException | NoSuchAlgorithmException | InvalidKeyException
                | NoSuchProviderException | SignatureException e) {
            log.error("Failed to verify X509 certificate signature.\nParent: {}\nChild: {}", parent, child, e);
            return false;
        }
    }

    public boolean verify(X509CRL crl, X509Certificate parent) {
        try {
            crl.verify(parent.getPublicKey());
            return true;
        } catch (CRLException | NoSuchAlgorithmException | InvalidKeyException
                | NoSuchProviderException | SignatureException e) {
            log.debug("Failed to verify X509 CRL signature.\nCertificate subject: {}\nCRL issuer: {}\nmessage: {}",
                parent.getSubjectX500Principal(), crl.getIssuerX500Principal(), e.getMessage());
            return false;
        }
    }
}

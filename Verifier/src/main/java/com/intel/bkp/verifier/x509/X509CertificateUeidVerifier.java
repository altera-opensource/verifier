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

package com.intel.bkp.verifier.x509;

import com.intel.bkp.verifier.model.dice.UeidExtensionParser;
import lombok.extern.slf4j.Slf4j;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;

import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Optional;

import static com.intel.bkp.ext.core.certificate.X509CertificateUtils.containsExtension;
import static com.intel.bkp.ext.utils.HexConverter.toHex;
import static com.intel.bkp.verifier.model.AttestationOid.TCG_DICE_UEID;

@Slf4j
public class X509CertificateUeidVerifier {

    private List<X509Certificate> certificates = new ArrayList<>();

    public X509CertificateUeidVerifier certificates(List<X509Certificate> certificates) {
        this.certificates = certificates;
        return this;
    }

    public boolean verify(byte[] deviceId) {
        return certificates.stream().allMatch(c -> verifyCertificate(c, deviceId));
    }

    public boolean verifyCertificate(final X509Certificate certificate, final byte[] deviceId) {
        if (!containsUeidExtension(certificate)) {
            log.debug("Certificate does not contain UEID extension: {}", certificate.getSubjectDN());
            return true;
        }

        final Optional<byte[]> uid = getUidFromUeidExtension(certificate);
        if (uid.isEmpty()) {
            return false;
        }

        final boolean valid = Arrays.equals(deviceId, uid.get());
        if (!valid) {
            log.error("Certificate has UEID extension with uid that does not match deviceId: {}"
                + "\nExpected: {}\nActual: {}", certificate.getSubjectDN(), toHex(deviceId), toHex(uid.get()));
        }

        return valid;
    }

    private boolean containsUeidExtension(final X509Certificate certificate) {
        final var ueidOid = new ASN1ObjectIdentifier(TCG_DICE_UEID.getOid());
        return containsExtension(certificate, ueidOid);
    }

    private Optional<byte[]> getUidFromUeidExtension(final X509Certificate certificate) {
        try {
            final var ueidParser = new UeidExtensionParser();
            ueidParser.parse(certificate);
            return Optional.of(ueidParser.getUeidExtension().getUid());
        } catch (Exception ex) {
            log.error("Failed to parse UEID extension of certificate: {}", certificate.getSubjectDN());
            return Optional.empty();
        }
    }
}

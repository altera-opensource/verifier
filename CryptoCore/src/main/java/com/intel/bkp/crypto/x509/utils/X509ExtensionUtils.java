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

package com.intel.bkp.crypto.x509.utils;

import lombok.AccessLevel;
import lombok.NoArgsConstructor;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1OctetString;

import java.security.cert.X509CRL;
import java.security.cert.X509CRLEntry;
import java.security.cert.X509Certificate;
import java.security.cert.X509Extension;
import java.util.HashSet;
import java.util.Optional;
import java.util.Set;

import static com.intel.bkp.utils.HexConverter.toHex;

@NoArgsConstructor(access = AccessLevel.PRIVATE)
public class X509ExtensionUtils {

    /**
     * Checks if certificate or CRL entry contains extension with specified oid, either as critical or non-critical.
     */
    public static boolean containsExtension(final X509Extension obj, ASN1ObjectIdentifier extensionOid) {
        return containsExtension(obj, extensionOid.getId());
    }

    public static boolean containsExtension(final X509Extension obj, String extensionOid) {
        final Set<String> allExtOids = new HashSet<>();
        Optional.ofNullable(obj.getCriticalExtensionOIDs()).ifPresent(allExtOids::addAll);
        Optional.ofNullable(obj.getNonCriticalExtensionOIDs()).ifPresent(allExtOids::addAll);
        return allExtOids.contains(extensionOid);
    }

    public static Optional<byte[]> getExtensionBytes(final X509Extension obj,
                                                     ASN1ObjectIdentifier extensionOid) {
        return getExtensionBytes(obj, extensionOid.getId());
    }

    public static Optional<byte[]> getExtensionBytes(final X509Extension obj, String extensionOid) {
        return Optional.ofNullable(obj.getExtensionValue(extensionOid))
            .map(ASN1OctetString::getInstance)
            .map(ASN1OctetString::getOctets);
    }

    public static String getObjDescription(final X509Extension x509Obj) {
        if (x509Obj instanceof X509Certificate cert) {
            return getCertificateDescription(cert);
        }
        if (x509Obj instanceof X509CRLEntry crlEntry) {
            return getCrlEntryDescription(crlEntry);
        }
        if (x509Obj instanceof X509CRL crl) {
            return getCrlDescription(crl);
        }
        return getDefaultDescription(x509Obj);
    }

    private static String getCertificateDescription(X509Certificate cert) {
        return "certificate: " + cert.getSubjectX500Principal();
    }

    private static String getCrlEntryDescription(X509CRLEntry crlEntry) {
        return "CRL entry with serial number: " + toHex(crlEntry.getSerialNumber().toByteArray());
    }

    private static String getCrlDescription(X509CRL crl) {
        return "CRL issued by: " + crl.getIssuerX500Principal();
    }

    private static String getDefaultDescription(X509Extension x509Obj) {
        return "object: " + x509Obj.toString();
    }
}

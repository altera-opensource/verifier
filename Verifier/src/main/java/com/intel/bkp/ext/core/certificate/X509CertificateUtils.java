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

package com.intel.bkp.ext.core.certificate;

import com.intel.bkp.ext.crypto.CryptoUtils;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.x509.AuthorityKeyIdentifier;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.SubjectKeyIdentifier;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;

import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PublicKey;
import java.security.SignatureException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Optional;

public class X509CertificateUtils {

    /**
     * Gets bytes of key identifier from AuthorityKeyIdentifier extension or null, if certificate doesn't contain it.
     */
    public static byte[] getAuthorityKeyIdentifier(final X509Certificate certificate) {
        return Optional.ofNullable(certificate.getExtensionValue(Extension.authorityKeyIdentifier.getId()))
            .map(ASN1OctetString::getInstance)
            .map(ASN1OctetString::getOctets)
            .map(AuthorityKeyIdentifier::getInstance)
            .map(AuthorityKeyIdentifier::getKeyIdentifier)
            .orElse(null);
    }

    /**
     * Calculates SubjectKeyIdentifier for public key, using method 2 defined in RFC7093:
     * "The keyIdentifier is composed of the leftmost 160-bits of the
     * SHA-384 hash of the value of the BIT STRING subjectPublicKey
     * (excluding the tag, length, and number of unused bits)."
     */
    public static byte[] calculateSubjectKeyIdentifierUsingMethod2FromRfc7093(final PublicKey publicKey) {
        final var subjectPublicKeyInfo = SubjectPublicKeyInfo.getInstance(publicKey.getEncoded());
        return CryptoUtils.get20MSBytesForSha384(subjectPublicKeyInfo.getPublicKeyData().getBytes());
    }

    /**
     * Gets bytes of key identifier from SubjectKeyIdentifier extension or null, if certificate doesn't contain it.
     */
    public static byte[] getSubjectKeyIdentifier(final X509Certificate certificate) {
        return Optional.ofNullable(certificate.getExtensionValue(Extension.subjectKeyIdentifier.getId()))
            .map(ASN1OctetString::getInstance)
            .map(ASN1OctetString::getOctets)
            .map(SubjectKeyIdentifier::getInstance)
            .map(SubjectKeyIdentifier::getKeyIdentifier)
            .orElse(null);
    }

    /**
     * Checks if certificate is self-signed, by comparing Subject and Issuer that must be equal and verifying that
     * certificate was signed using its own public key.
     *
     * @return true if both conditions are met, false otherwise.
     */
    public static boolean isSelfSigned(final X509Certificate certificate) {
        if (!certificate.getIssuerX500Principal().equals(certificate.getSubjectX500Principal())) {
            return false;
        }

        try {
            certificate.verify(certificate.getPublicKey());
            return true;
        } catch (CertificateException | NoSuchAlgorithmException | InvalidKeyException
            | NoSuchProviderException | SignatureException e) {
            return false;
        }
    }

    /**
     * Checks if certificate contains extension with specified oid, either as critical or non-critical.
     */
    public static boolean containsExtension(final X509Certificate certificate, ASN1ObjectIdentifier extensionOid) {
        final String oid = extensionOid.getId();
        return certificate.getCriticalExtensionOIDs().contains(oid)
            || certificate.getNonCriticalExtensionOIDs().contains(oid);
    }
}

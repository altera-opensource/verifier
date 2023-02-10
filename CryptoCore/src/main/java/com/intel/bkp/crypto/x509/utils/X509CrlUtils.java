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

import com.intel.bkp.crypto.CryptoUtils;
import com.intel.bkp.crypto.pem.PemFormatEncoder;
import com.intel.bkp.crypto.pem.PemFormatHeader;
import com.intel.bkp.utils.HexConverter;
import lombok.AccessLevel;
import lombok.NoArgsConstructor;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.cert.X509CRLHolder;
import org.bouncycastle.cert.jcajce.JcaX509CRLConverter;

import java.math.BigInteger;
import java.security.cert.CRLException;
import java.security.cert.X509CRL;
import java.security.cert.X509CRLEntry;
import java.util.Collections;
import java.util.List;
import java.util.Optional;
import java.util.stream.Collectors;
import java.util.stream.Stream;

@NoArgsConstructor(access = AccessLevel.PRIVATE)
public class X509CrlUtils {

    public static boolean isRevoked(final X509CRL crl, final BigInteger serialNumber) {
        return isRevoked(getX509CRLEntries(crl), serialNumber);
    }

    public static boolean isRevoked(final Stream<? extends X509CRLEntry> crlEntries, final BigInteger serialNumber) {
        return crlEntries
            .map(X509CRLEntry::getSerialNumber)
            .anyMatch(sn -> sn.equals(serialNumber));
    }

    public static List<String> getRevokedSerialNumbersInHex(final X509CRL crl) {
        return getRevokedSerialNumbers(crl)
            .map(BigInteger::toByteArray)
            .map(HexConverter::toHex)
            .collect(Collectors.toList());
    }

    private static Stream<? extends BigInteger> getRevokedSerialNumbers(final X509CRL crl) {
        return getX509CRLEntries(crl)
            .map(X509CRLEntry::getSerialNumber);
    }

    public static Stream<? extends X509CRLEntry> getX509CRLEntries(X509CRL crl) {
        return Optional
            .ofNullable(crl.getRevokedCertificates())
            .orElse(Collections.emptySet())
            .stream();
    }

    public static BigInteger getCrlNumber(final X509CRL crl) {
        final byte[] encodedExtValue = crl.getExtensionValue(Extension.cRLNumber.getId());
        final byte[] extValue = DEROctetString.getInstance(encodedExtValue).getOctets();
        final long baseCrlNumber = ASN1Integer.getInstance(extValue).getPositiveValue().longValue();
        return BigInteger.valueOf(baseCrlNumber);
    }

    public static String toPem(X509CRL crl) throws CRLException {
        return PemFormatEncoder.encode(PemFormatHeader.CRL, crl.getEncoded());
    }

    public static X509CRL getCrl(X509CRLHolder holder) throws CRLException {
        return new JcaX509CRLConverter()
                .setProvider(CryptoUtils.getBouncyCastleProvider())
                .getCRL(holder);
    }
}

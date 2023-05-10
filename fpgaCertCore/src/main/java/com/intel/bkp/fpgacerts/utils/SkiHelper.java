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

package com.intel.bkp.fpgacerts.utils;

import com.intel.bkp.utils.Base64Url;
import lombok.AccessLevel;
import lombok.NoArgsConstructor;
import org.apache.commons.lang3.ArrayUtils;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;

import java.security.PublicKey;
import java.security.cert.X509Certificate;
import java.util.Arrays;

import static com.intel.bkp.crypto.impl.HashUtils.getMSBytesForSha384;
import static com.intel.bkp.crypto.x509.utils.KeyIdentifierUtils.getSubjectKeyIdentifier;

/**
 * Used for dice certs which should use EC key not RSA.
 */
@NoArgsConstructor(access = AccessLevel.PRIVATE)
public class SkiHelper {

    /**
     * Get first 20 bytes of SKI in BASE64 URL without padding.
     *
     * @param certificate - Assumed certificate contains SKI extension that was calculated using SHA384
     * @return string
     */
    public static String getFirst20BytesOfSkiInBase64Url(X509Certificate certificate) {
        final byte[] ski = getSubjectKeyIdentifier(certificate);
        final byte[] first20Bytes = Arrays.copyOf(ski, 20);
        return Base64Url.encodeWithoutPadding(first20Bytes);
    }

    public static String getFirst20BytesOfSkiInBase64Url(byte[] xyBytes) {
        final byte[] publicKeyWithAppendedUncompressedByte = ArrayUtils.addAll(new byte[]{0x04}, xyBytes);
        final byte[] first20Bytes = getMSBytesForSha384(publicKeyWithAppendedUncompressedByte, 20);
        return Base64Url.encodeWithoutPadding(first20Bytes);
    }

    public static String getFirst12BytesOfSkiInBase64Url(PublicKey publicKey) {
        final var subjectPublicKeyInfo = SubjectPublicKeyInfo.getInstance(publicKey.getEncoded());
        final byte[] publicKeyWithAppendedUncompressedByte = subjectPublicKeyInfo.getPublicKeyData().getBytes();
        final byte[] first12Bytes = getMSBytesForSha384(publicKeyWithAppendedUncompressedByte, 12);
        return Base64Url.encodeWithoutPadding(first12Bytes);
    }
}

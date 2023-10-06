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
import java.util.Arrays;

import static com.intel.bkp.crypto.impl.HashUtils.getMSBytesForSha384;

/**
 * Used for dice certs which should use EC key not RSA.
 */
@NoArgsConstructor(access = AccessLevel.PRIVATE)
public class SkiHelper {

    public static final int RIM_BYTES_FOR_URL = 21;
    public static final int BYTES_FOR_URL = 20;
    public static final int BYTES_FOR_DICE_CERT_SUBJECT = 12;

    public static String getSkiInBase64UrlForUrl(byte[] xyBytes) {
        final byte[] publicKeyWithAppendedUncompressedByte = ArrayUtils.addAll(new byte[]{0x04}, xyBytes);
        return getMSBytesOfSkiInBase64Url(BYTES_FOR_URL, publicKeyWithAppendedUncompressedByte);
    }

    public static String getSkiInBase64UrlForUrl(PublicKey publicKey) {
        return getMSBytesOfSkiInBase64Url(BYTES_FOR_URL, getPublicKeyWithAppendedUncompressedByte(publicKey));
    }

    public static String getFwIdInBase64UrlForUrl(byte[] digest) {
        final byte[] msb = Arrays.copyOfRange(digest, 0, RIM_BYTES_FOR_URL);
        return Base64Url.encodeWithoutPadding(msb);
    }

    public static String getSkiInBase64UrlForDiceSubject(PublicKey publicKey) {
        return getMSBytesOfSkiInBase64Url(BYTES_FOR_DICE_CERT_SUBJECT,
            getPublicKeyWithAppendedUncompressedByte(publicKey));
    }

    public static String getPdiForUrlFrom(byte[] deviceIdentity) {
        return Base64Url.encodeWithoutPadding(Arrays.copyOf(deviceIdentity, BYTES_FOR_URL));
    }

    private static byte[] getPublicKeyWithAppendedUncompressedByte(PublicKey publicKey) {
        return SubjectPublicKeyInfo.getInstance(publicKey.getEncoded())
            .getPublicKeyData()
            .getBytes();
    }

    private static String getMSBytesOfSkiInBase64Url(int bytesCount, byte[] data) {
        final byte[] leadingBytes = getMSBytesForSha384(data, bytesCount);
        return Base64Url.encodeWithoutPadding(leadingBytes);
    }
}

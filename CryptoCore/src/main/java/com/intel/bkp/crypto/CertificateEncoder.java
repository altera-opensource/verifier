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

package com.intel.bkp.crypto;

import com.intel.bkp.crypto.constants.SecurityKeyType;
import com.intel.bkp.crypto.exceptions.CertificateEncoderException;
import lombok.AccessLevel;
import lombok.NoArgsConstructor;

import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.util.Base64;

import static com.intel.bkp.utils.HexConverter.fromHex;

@NoArgsConstructor(access = AccessLevel.PRIVATE)
public class CertificateEncoder {

    public static final String BOUNDARY_REGEX = "([\\-]+)([A-Z\\s]+)([\\-]+)";

    public static PublicKey toPublicKey(String pubKeyData, SecurityKeyType securityKeyType)
        throws CertificateEncoderException {
        try {
            return CryptoUtils.toPublicEncodedBC(sanitizeChainPayloadBase64(pubKeyData), securityKeyType.name());
        } catch (NoSuchAlgorithmException | InvalidKeySpecException e) {
            throw new CertificateEncoderException(e);
        }
    }

    public static byte[] sanitizeChainPayloadBase64(String pubKey) {
        return Base64.getDecoder().decode(sanitize(pubKey));
    }

    public static byte[] sanitizeChainPayloadHex(String data) {
        return fromHex(sanitize(data));
    }

    private static String sanitize(String data) {
        return data.replaceAll(BOUNDARY_REGEX, "").replaceAll("[\r\n]", "");
    }
}

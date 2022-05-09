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
import com.intel.bkp.crypto.exceptions.KeystoreGenericException;
import com.intel.bkp.crypto.pem.PemFormatEncoder;
import com.intel.bkp.crypto.pem.PemFormatHeader;
import org.apache.commons.codec.binary.Hex;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

import java.security.KeyPair;
import java.security.PublicKey;
import java.util.Base64;

import static com.intel.bkp.utils.HexConverter.toHex;

public class CertificateEncoderTest {

    private static final String INPUT_DATA = "-----BEGIN PUBLIC KEY-----\n%s\n-----END PUBLIC KEY-----";
    private static final byte[] EXPECTED_BYTES = new byte[]{0, 1, 2, 3, 4};

    @Test
    void toPublicKey_WithRSAKey_Success() throws Exception {
        // given
        final KeyPair keyPair = TestUtil.genRsaKeys();
        final String pemEncodedPublicKey = PemFormatEncoder.encode(PemFormatHeader.PUBLIC_KEY,
            keyPair.getPublic().getEncoded());

        // when
        final PublicKey key = CertificateEncoder.toPublicKey(pemEncodedPublicKey, SecurityKeyType.RSA);

        // then
        Assertions.assertEquals(
            Hex.encodeHexString(keyPair.getPublic().getEncoded()),
            Hex.encodeHexString(key.getEncoded())
        );
    }

    @Test
    void toPublicKey_WithDifferentPubKey_ThrowsException() throws KeystoreGenericException {
        // given
        final KeyPair keyPair = TestUtil.genEcKeys();
        final String pemEncodedPublicKey = PemFormatEncoder.encode(PemFormatHeader.PUBLIC_KEY,
            keyPair.getPublic().getEncoded());

        // when-then
        Assertions.assertThrows(
            CertificateEncoderException.class,
            () -> CertificateEncoder.toPublicKey(pemEncodedPublicKey, SecurityKeyType.RSA)
        );
    }

    @Test
    void toPublicKey_WithNotPublicKey_ThrowsException() {
        // given
        final String pemEncodedPublicKey = "Test";

        // when-then
        Assertions.assertThrows(
            CertificateEncoderException.class,
            () -> CertificateEncoder.toPublicKey(pemEncodedPublicKey, SecurityKeyType.RSA)
        );
    }

    @Test
    void sanitizeChainPayloadBase64_SuccessfullyEncodesData() {
        // given
        String testKey = String.format(INPUT_DATA, Base64.getEncoder().encodeToString(EXPECTED_BYTES));

        // when
        final byte[] result = CertificateEncoder.sanitizeChainPayloadBase64(testKey);

        // then
        Assertions.assertNotNull(result);
        Assertions.assertArrayEquals(EXPECTED_BYTES, result);
    }

    @Test
    void sanitizeChainPayloadHex_SuccessfullyEncodesData() {
        // given
        String testKey = String.format(INPUT_DATA, toHex(EXPECTED_BYTES));

        // when
        final byte[] result = CertificateEncoder.sanitizeChainPayloadHex(testKey);

        // then
        Assertions.assertNotNull(result);
        Assertions.assertArrayEquals(EXPECTED_BYTES, result);
    }
}

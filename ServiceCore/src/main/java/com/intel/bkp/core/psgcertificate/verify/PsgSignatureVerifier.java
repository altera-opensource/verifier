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

package com.intel.bkp.core.psgcertificate.verify;

import com.intel.bkp.core.endianess.EndianessActor;
import com.intel.bkp.core.psgcertificate.PsgCertificateHelper;
import com.intel.bkp.core.psgcertificate.PsgPublicKeyBuilder;
import com.intel.bkp.core.psgcertificate.PsgPublicKeyHelper;
import com.intel.bkp.core.psgcertificate.PsgSignatureBuilder;
import com.intel.bkp.core.psgcertificate.exceptions.PsgCertificateException;
import com.intel.bkp.core.psgcertificate.exceptions.PsgInvalidSignatureException;
import com.intel.bkp.core.psgcertificate.model.PsgSignatureCurveType;

import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;

import static com.intel.bkp.crypto.constants.CryptoConstants.SHA256_WITH_ECDSA;
import static com.intel.bkp.crypto.constants.CryptoConstants.SHA384_WITH_ECDSA;

public class PsgSignatureVerifier {

    public static boolean isValid(PsgPublicKeyBuilder publicKeyBuilder, PsgSignatureBuilder signatureBuilder,
                                  byte[] payload) throws PsgCertificateException, InvalidKeySpecException,
        NoSuchAlgorithmException, PsgInvalidSignatureException {

        verifyIfPublicKeyIsValid(publicKeyBuilder);

        final String signatureAlgorithm = getSignatureAlgorithm(signatureBuilder.getSignatureType());
        final PublicKey publicKey = PsgPublicKeyHelper.toPublic(publicKeyBuilder);
        return PsgCertificateHelper.sigVerify(signatureAlgorithm, publicKey, payload, signatureBuilder);
    }

    private static void verifyIfPublicKeyIsValid(PsgPublicKeyBuilder builder) throws PsgCertificateException {
        builder.withActor(EndianessActor.FIRMWARE).verify();
    }

    private static String getSignatureAlgorithm(PsgSignatureCurveType signatureType) {
        return signatureType == PsgSignatureCurveType.SECP384R1 ? SHA384_WITH_ECDSA : SHA256_WITH_ECDSA;
    }
}

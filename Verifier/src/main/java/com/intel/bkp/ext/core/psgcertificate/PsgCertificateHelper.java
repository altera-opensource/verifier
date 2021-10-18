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

package com.intel.bkp.ext.core.psgcertificate;

import com.intel.bkp.ext.core.psgcertificate.exceptions.PsgInvalidSignatureException;
import com.intel.bkp.ext.crypto.CryptoUtils;
import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Encoding;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1OutputStream;
import org.bouncycastle.asn1.DERSequence;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.Signature;
import java.security.SignatureException;

public class PsgCertificateHelper {

    private static final String FAILED_TO_CHECK_SIGNATURE = "Failed to check signature";

    public static boolean sigVerify(String signatureAlgorithm, PublicKey publicKey, byte[] data,
                                    PsgSignatureBuilder signatureBuilder) throws PsgInvalidSignatureException {
        try {
            Signature ecdsaSign = Signature.getInstance(signatureAlgorithm, CryptoUtils.getBouncyCastleProvider());
            ecdsaSign.initVerify(publicKey);
            ecdsaSign.update(data);
            return ecdsaSign.verify(convertToDerSignature(signatureBuilder.getSignatureR(),
                signatureBuilder.getSignatureS()));
        } catch (NoSuchAlgorithmException | InvalidKeyException | SignatureException | IOException e) {
            throw new PsgInvalidSignatureException(FAILED_TO_CHECK_SIGNATURE, e);
        }
    }

    private static byte[] convertToDerSignature(byte[] partR, byte[] partS) throws IOException {
        try (ByteArrayOutputStream byteArrayOutputStream = new ByteArrayOutputStream()) {
            ASN1OutputStream derOutputStream = ASN1OutputStream.create(byteArrayOutputStream, ASN1Encoding.DER);
            ASN1EncodableVector vector = new ASN1EncodableVector();
            vector.add(new ASN1Integer(new BigInteger(1, partR)));
            vector.add(new ASN1Integer(new BigInteger(1, partS)));
            derOutputStream.writeObject(new DERSequence(vector));
            return byteArrayOutputStream.toByteArray();
        }
    }
}

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

package com.intel.bkp.core.psgcertificate;

import com.intel.bkp.core.utils.PublicKeyHelperBase;
import com.intel.bkp.crypto.CryptoUtils;
import com.intel.bkp.crypto.curve.CurvePoint;

import java.security.interfaces.ECPublicKey;

import static com.intel.bkp.crypto.CryptoUtils.getBytesFromPubKey;
import static com.intel.bkp.crypto.CryptoUtils.getPubKeyXYLenForPubKey;

public class PsgPublicKeyHelper extends PublicKeyHelperBase {


    public PsgPublicKeyHelper(CurvePoint point) {
        super(point);
    }

    public static PsgPublicKeyHelper from(PsgPublicKeyBuilder psgPublicKeyBuilder) {
        return new PsgPublicKeyHelper(psgPublicKeyBuilder.getCurvePoint());
    }

    public static PsgPublicKeyHelper from(byte[] data) {
        return new PsgPublicKeyHelper(new PsgPublicKeyBuilder().parse(data).getCurvePoint());
    }

    public String generateFingerprint() {
        return getPoint().generateFingerprint();
    }

    public String generateSha256Fingerprint() {
        return getPoint().generateSha256Fingerprint();
    }

    public boolean areEqual(ECPublicKey pubKey) {
        final byte[] bytesFromPubKey = getBytesFromPubKey(pubKey, getPubKeyXYLenForPubKey(pubKey));
        return CryptoUtils.generateFingerprint(bytesFromPubKey).equals(generateFingerprint());
    }
}

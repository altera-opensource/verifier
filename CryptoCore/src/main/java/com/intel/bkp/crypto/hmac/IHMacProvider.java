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

package com.intel.bkp.crypto.hmac;

import com.intel.bkp.crypto.CryptoUtils;
import com.intel.bkp.crypto.exceptions.HMacProviderException;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.nio.ByteBuffer;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.Provider;
import java.util.Arrays;

import static com.intel.bkp.utils.HexConverter.toHex;

public interface IHMacProvider {

    String getAlgorithmType();

    byte[] getMasterKey();

    default Provider getProvider() {
        return CryptoUtils.getBouncyCastleProvider();
    }

    static void validateHmac(byte[] expected, byte[] actual) throws HMacProviderException {
        if (!Arrays.equals(expected, actual)) {
            throw new HMacProviderException(String.format("HMAC verification failed. Expected: %s, Actual: %s",
                toHex(expected), toHex(actual)));
        }
    }

    default byte[] getHash(byte[] bytes) throws HMacProviderException {
        return getHash(ByteBuffer.allocate(bytes.length).put(bytes));
    }

    default byte[] getHash(ByteBuffer byteBuffer) throws HMacProviderException {
        try {
            final Mac hmac = Mac.getInstance(getAlgorithmType(), getProvider());
            SecretKeySpec masterKeySpec = new SecretKeySpec(getMasterKey(), getAlgorithmType());
            hmac.reset();
            hmac.init(masterKeySpec);
            return hmac.doFinal(byteBuffer.array());
        } catch (NoSuchAlgorithmException | InvalidKeyException e) {
            throw new HMacProviderException("Failed to calculate hash.", e);
        }
    }

}

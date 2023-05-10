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

package com.intel.bkp.crypto.aesgcm;

import com.intel.bkp.crypto.exceptions.EncryptionProviderException;
import com.intel.bkp.crypto.interfaces.IEncryptionProvider;
import com.intel.bkp.utils.ByteBufferSafe;
import com.intel.bkp.utils.exceptions.ByteBufferSafeException;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.security.Provider;
import java.security.SecureRandom;
import java.util.Optional;

public abstract class AesGcmProvider implements IEncryptionProvider {

    private static final int AUTH_TAG_LEN_BITS = 128;
    private static final int IV_LEN_BYTES = 12;

    public abstract SecretKey getSecretKey();

    public abstract Provider getProvider();

    public abstract String getCipherType();

    public abstract ByteOrder getByteOrder();

    public byte[] encrypt(byte[] data) throws EncryptionProviderException {
        final byte[] iv = generateIV();
        final byte[] encryptedBytes = perform(iv, data, Cipher.ENCRYPT_MODE);

        ByteBuffer byteBuffer = ByteBuffer
            .allocate(Integer.BYTES + iv.length + encryptedBytes.length)
            .order(getByteOrderInternal());
        return byteBuffer.putInt(iv.length).put(iv).put(encryptedBytes).array();
    }

    public byte[] decrypt(byte[] data) throws EncryptionProviderException {
        try {
            ByteBufferSafe byteBuffer = ByteBufferSafe.wrap(data).order(getByteOrderInternal());

            byte[] iv = byteBuffer.arrayFromNextInt();
            if (iv.length != IV_LEN_BYTES) {
                throw new EncryptionProviderException("Invalid iv length.");
            }

            byteBuffer.get(iv);

            byte[] cipherText = byteBuffer.arrayFromRemaining();
            byteBuffer.get(cipherText);

            return perform(iv, cipherText, Cipher.DECRYPT_MODE);
        } catch (ByteBufferSafeException e) {
            throw new EncryptionProviderException("Data to decrypt for AesGcm is incorrect.", e);
        }
    }

    private byte[] generateIV() {
        SecureRandom secureRandom = new SecureRandom();

        // (https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-38d.pdf p.19)
        byte[] iv = new byte[IV_LEN_BYTES];
        secureRandom.nextBytes(iv);
        return iv;
    }

    private byte[] perform(byte[] iv, byte[] data, int mode) throws EncryptionProviderException {
        try {
            final Cipher cipher = Cipher.getInstance(getCipherTypeInternal(), getProviderInternal());
            cipher.init(mode, getSecretKeyInternal(), new GCMParameterSpec(AUTH_TAG_LEN_BITS, iv));
            cipher.updateAAD(new byte[0]);
            return cipher.doFinal(data);
        } catch (EncryptionProviderException e) {
            throw e;
        } catch (Exception e) {
            if (mode == Cipher.ENCRYPT_MODE) {
                throw new EncryptionProviderException("AES encryption failed.", e);
            } else {
                throw new EncryptionProviderException("AES decryption failed.", e);
            }
        }
    }

    private SecretKey getSecretKeyInternal() throws EncryptionProviderException {
        return Optional.ofNullable(getSecretKey())
            .orElseThrow(() -> new EncryptionProviderException("Context Key is not set."));
    }

    private Provider getProviderInternal() throws EncryptionProviderException {
        return Optional.ofNullable(getProvider())
            .orElseThrow(() -> new EncryptionProviderException("Provider is not set."));
    }

    private String getCipherTypeInternal() throws EncryptionProviderException {
        return Optional.ofNullable(getCipherType())
            .filter(s -> !s.isEmpty() && !s.isBlank())
            .orElseThrow(() -> new EncryptionProviderException("Cipher type is not set."));
    }

    private ByteOrder getByteOrderInternal() throws EncryptionProviderException {
        return Optional.ofNullable(getByteOrder())
            .orElseThrow(() -> new EncryptionProviderException("ByteOrder is not set."));
    }
}

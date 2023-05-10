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

import com.intel.bkp.core.endianness.StructureBuilder;
import com.intel.bkp.core.endianness.StructureType;
import com.intel.bkp.core.exceptions.ParseStructureException;
import com.intel.bkp.core.psgcertificate.enumerations.KeyWrappingType;
import com.intel.bkp.core.psgcertificate.enumerations.StorageType;
import com.intel.bkp.core.psgcertificate.model.PsgAesKey;
import com.intel.bkp.utils.ByteBufferSafe;
import com.intel.bkp.utils.exceptions.ByteBufferSafeException;
import lombok.Getter;

import java.math.BigInteger;

import static com.intel.bkp.core.endianness.StructureField.PSG_AES_KEY_CERT_DATA_LENGTH;
import static com.intel.bkp.core.endianness.StructureField.PSG_AES_KEY_CERT_TYPE;
import static com.intel.bkp.core.endianness.StructureField.PSG_AES_KEY_CERT_VERSION;
import static com.intel.bkp.core.endianness.StructureField.PSG_AES_KEY_MAGIC;
import static com.intel.bkp.core.endianness.StructureField.PSG_AES_KEY_USER_AES_CERT_MAGIC;

@Getter
public class PsgAesKeyBuilder extends StructureBuilder<PsgAesKeyBuilder, PsgAesKey> {

    public static final int MAGIC = 0x25D04E7F;
    public static final int USER_AES_CERT_MAGIC = 0xD0850CAA;

    private static final int ENTRY_BASIC_SIZE = 0x50;

    private static final int RESERVED_LEN = 10;
    private static final int USER_INPUT_IV_LEN = 16;
    private static final int USER_AES_ROOT_KEY_LEN = 32;
    private static final int RESERVED_SECOND_LEN = 48;

    private byte[] magic = new byte[Integer.BYTES];
    private byte[] certDataLength = new byte[Integer.BYTES];
    private byte[] certVersion = new byte[Integer.BYTES];
    private byte[] certType = new byte[Integer.BYTES];
    private byte[] userAesCertMagic = new byte[Integer.BYTES];
    private StorageType storageType;
    private KeyWrappingType keyWrappingType;
    private final byte[] reserved = new byte[RESERVED_LEN];
    private final byte[] userInputIV = new byte[USER_INPUT_IV_LEN];
    private final byte[] userAesRootKey = new byte[USER_AES_ROOT_KEY_LEN];
    private final byte[] reservedSecond = new byte[RESERVED_SECOND_LEN];
    private byte[] certSigningKeyChain = new byte[0];

    public PsgAesKeyBuilder() {
        super(StructureType.PSG_AES_KEY_ENTRY);
    }

    @Override
    public PsgAesKeyBuilder self() {
        return this;
    }

    @Override
    public PsgAesKey build() {
        PsgAesKey entry = new PsgAesKey();

        entry.setMagic(convert(MAGIC, PSG_AES_KEY_MAGIC));
        entry.setCertDataLength(convert(certDataLength, PSG_AES_KEY_CERT_DATA_LENGTH));
        entry.setCertVersion(convert(certVersion, PSG_AES_KEY_CERT_VERSION));
        entry.setCertType(convert(certType, PSG_AES_KEY_CERT_TYPE));
        entry.setUserAesCertMagic(convert(userAesCertMagic, PSG_AES_KEY_USER_AES_CERT_MAGIC));
        entry.setKeyStorageType(storageType.getType().byteValue());
        entry.setKeyWrappingType(keyWrappingType.getType().byteValue());
        entry.setReserved(reserved);
        entry.setUserInputIV(userInputIV);
        entry.setUserAesRootKey(userAesRootKey);
        entry.setReservedSecond(reservedSecond);
        entry.setCertSigningKeyChain(certSigningKeyChain);

        return entry;
    }

    @Override
    public PsgAesKeyBuilder parse(ByteBufferSafe buffer) throws ParseStructureException {
        try {
            buffer.get(magic);
            magic = convert(magic, PSG_AES_KEY_MAGIC);
            if (MAGIC != new BigInteger(magic).intValue()) {
                throw new ParseStructureException("Invalid entry magic");
            }

            buffer.get(certDataLength);
            certDataLength = convert(certDataLength, PSG_AES_KEY_CERT_DATA_LENGTH);
            buffer.get(certVersion);
            certVersion = convert(certVersion, PSG_AES_KEY_CERT_VERSION);
            buffer.get(certType);
            certType = convert(certType, PSG_AES_KEY_CERT_TYPE);

            buffer.get(userAesCertMagic);
            userAesCertMagic = convert(userAesCertMagic, PSG_AES_KEY_USER_AES_CERT_MAGIC);
            if (USER_AES_CERT_MAGIC != new BigInteger(userAesCertMagic).intValue()) {
                throw new ParseStructureException("Invalid user aes entry magic");
            }

            storageType = StorageType.fromValue(buffer.getByte());
            keyWrappingType = KeyWrappingType.fromValue(buffer.getByte());
            buffer.get(reserved);
            buffer.get(userInputIV);
            buffer.get(userAesRootKey);
            buffer.get(reservedSecond);
            certSigningKeyChain = buffer.arrayFromRemaining();
            buffer.get(certSigningKeyChain);

            return this;
        } catch (ByteBufferSafeException e) {
            throw new ParseStructureException("Invalid buffer during parsing entry", e);
        }
    }
}

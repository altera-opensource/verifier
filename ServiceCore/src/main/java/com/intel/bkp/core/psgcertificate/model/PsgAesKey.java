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

package com.intel.bkp.core.psgcertificate.model;

import com.intel.bkp.core.interfaces.IStructure;
import com.intel.bkp.core.psgcertificate.PsgCertificateCommon;
import lombok.Getter;
import lombok.Setter;

import java.nio.ByteBuffer;

@Getter
@Setter
public class PsgAesKey implements IStructure, PsgCertificateCommon {

    private byte[] magic = new byte[0];
    private byte[] certDataLength = new byte[0];
    private byte[] certVersion = new byte[0];
    private byte[] certType = new byte[0];
    private byte[] userAesCertMagic = new byte[0];
    private byte keyStorageType = 0x00;
    private byte keyWrappingType = 0x00;
    private byte[] reserved = new byte[0];
    private byte[] userInputIV = new byte[0];
    private byte[] userAesRootKey = new byte[0];
    private byte[] reservedSecond = new byte[0];
    private byte[] certSigningKeyChain = new byte[0];

    @Override
    public byte[] array() {
        final int capacity = magic.length + certDataLength.length + certVersion.length + certType.length
            + userAesCertMagic.length + (2 * Byte.BYTES) + reserved.length
            + userInputIV.length + userAesRootKey.length + reservedSecond.length + certSigningKeyChain.length;

        return ByteBuffer.allocate(
            capacity)
            .put(magic)
            .put(certDataLength)
            .put(certVersion)
            .put(certType)
            .put(userAesCertMagic)
            .put(keyStorageType)
            .put(keyWrappingType)
            .put(reserved)
            .put(userInputIV)
            .put(userAesRootKey)
            .put(reservedSecond)
            .put(certSigningKeyChain)
            .array();
    }
}

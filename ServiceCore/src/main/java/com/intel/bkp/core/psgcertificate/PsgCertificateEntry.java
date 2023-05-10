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

import com.intel.bkp.core.interfaces.IStructure;
import lombok.Getter;
import lombok.Setter;

import java.nio.ByteBuffer;

@Getter
@Setter
public class PsgCertificateEntry implements IStructure, IPsgCertificateWithPubKey, PsgCertificateCommon,
    IPsgCertificateWithSignature {

    private byte[] magic = new byte[0];
    private byte[] lengthOffset = new byte[0];
    private byte[] dataLength = new byte[0];
    private byte[] signatureLength = new byte[0];
    private byte[] shaLength = new byte[0];
    private byte[] reserved = new byte[0];
    private byte[] psgPublicKey = new byte[0];
    private byte[] psgSignature = new byte[0];

    @Override
    public byte[] array() {
        final int capacity = magic.length + lengthOffset.length + dataLength.length + signatureLength.length
            + shaLength.length + reserved.length + psgPublicKey.length + psgSignature.length;

        return ByteBuffer.allocate(
            capacity)
            .put(magic)
            .put(lengthOffset)
            .put(dataLength)
            .put(signatureLength)
            .put(shaLength)
            .put(reserved)
            .put(psgPublicKey)
            .put(psgSignature)
            .array();
    }
}

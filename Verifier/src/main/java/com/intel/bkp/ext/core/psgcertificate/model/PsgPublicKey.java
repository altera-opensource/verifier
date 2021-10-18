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

package com.intel.bkp.ext.core.psgcertificate.model;

import com.intel.bkp.ext.core.interfaces.IPsgFormat;
import com.intel.bkp.ext.utils.HexConverter;
import lombok.Getter;
import lombok.Setter;

import java.nio.ByteBuffer;

@Getter
@Setter
public class PsgPublicKey implements IPsgFormat {

    private byte[] magic = new byte[0];
    private byte[] sizeX = new byte[0];
    private byte[] sizeY = new byte[0];
    private byte[] curveMagic = new byte[0];
    private byte[] permissions = new byte[0];
    private byte[] cancellation = new byte[0];
    private byte[] pointX = new byte[0];
    private byte[] pointY = new byte[0];

    @Override
    public byte[] array() {
        final int capacity = magic.length + sizeX.length + sizeY.length + curveMagic.length + permissions.length
            + cancellation.length + pointX.length + pointY.length;
        return ByteBuffer.allocate(capacity)
            .put(magic)
            .put(sizeX)
            .put(sizeY)
            .put(curveMagic)
            .put(permissions)
            .put(cancellation)
            .put(pointX)
            .put(pointY)
            .array();
    }

    public String toHex() {
        return HexConverter.toHex(array());
    }
}

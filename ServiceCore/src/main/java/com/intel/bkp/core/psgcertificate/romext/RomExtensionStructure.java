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

package com.intel.bkp.core.psgcertificate.romext;

import com.intel.bkp.core.interfaces.IPsgFormat;
import lombok.Getter;
import lombok.Setter;

import java.nio.ByteBuffer;

@Getter
@Setter
public class RomExtensionStructure implements IPsgFormat {

    public static final int MAGIC_LEN = Integer.BYTES;
    public static final int LENGTH_LEN = Integer.BYTES;
    public static final int UNUSED_FIXED_SIZE_LEN = Integer.BYTES;
    public static final int EDI_ID_LEN = Integer.BYTES;
    public static final int FAMILY_ID_LEN = 1;
    public static final int BUILD_IDENTIFIER_LEN = 28;
    public static final int RESERVED_LEN = 3;

    private byte[] magic = new byte[MAGIC_LEN];
    private byte[] length = new byte[LENGTH_LEN];
    private byte[] unusedFixedSize = new byte[UNUSED_FIXED_SIZE_LEN];
    private byte[] ediId = new byte[EDI_ID_LEN];
    private byte[] unusedVarySize = new byte[0]; // dynamic
    private byte[] buildIdentifier = new byte[BUILD_IDENTIFIER_LEN];
    private byte[] familyId = new byte[FAMILY_ID_LEN];
    private byte[] reserved = new byte[RESERVED_LEN];
    private byte[] signature = new byte[0]; // dynamic

    @Override
    public byte[] array() {
        final ByteBuffer buffer = ByteBuffer.allocate(getPayloadSignatureCapacity());
        buffer.put(magic);
        buffer.put(length);
        buffer.put(unusedFixedSize);
        buffer.put(ediId);
        buffer.put(unusedVarySize);
        buffer.put(buildIdentifier);
        buffer.put(familyId);
        buffer.put(reserved);
        buffer.put(signature);
        return buffer.array();
    }

    private int getPayloadSignatureCapacity() {
        int capacity = countBaseCapacity();
        capacity += signature.length;
        return capacity;
    }

    private int countBaseCapacity() {
        int capacity = 0;
        capacity += magic.length;
        capacity += length.length;
        capacity += unusedFixedSize.length;
        capacity += ediId.length;
        capacity += unusedVarySize.length;
        capacity += buildIdentifier.length;
        capacity += familyId.length;
        capacity += reserved.length;
        return capacity;
    }
}

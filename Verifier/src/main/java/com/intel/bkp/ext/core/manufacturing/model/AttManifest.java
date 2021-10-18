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

package com.intel.bkp.ext.core.manufacturing.model;

import com.intel.bkp.ext.core.interfaces.IPsgFormat;
import com.intel.bkp.ext.core.manufacturing.AttManifestBuilder;
import lombok.Getter;
import lombok.Setter;

import java.nio.ByteBuffer;

@Getter
@Setter
public class AttManifest implements IPsgFormat {

    public static final int FAMILY_NAME_LEN = 20;
    public static final int ATTESTATION_KEYS_ARRAY_SIZE = 32;
    public static final int PUB_KEY_XY_LEN = 96;
    public static final int EFUSE_BLOCK_LEN = 128;
    public static final int COMMON_HASH_LEN = 48;

    private byte[] magic = new byte[Integer.BYTES];
    private byte[] length = new byte[Integer.BYTES]; // 8192
    private byte[] familyName = new byte[FAMILY_NAME_LEN]; // Zero terminated family name, (agilex, easic_n5x)
    private byte baseEdiId; // EDI_ID for DeviceID key (also called SVN)
    private byte familyIdentifier; // b27:20 from JTAG id, (0x34 for agilex, 0x35 for easic_n5x)
    private byte[] manifestKeyOffset = new byte[2]; // Offset to manifest signing key and manifest signature (MANKEY)
    private byte[] deviceId = new byte[Long.BYTES];
    private byte[] amsKeyId = new byte[Integer.BYTES];
    private byte[] reserved = new byte[Integer.BYTES];
    private byte[] efuseBlock = new byte[EFUSE_BLOCK_LEN];
    private byte[] romPatchEfuseHash = new byte[COMMON_HASH_LEN];
    private byte[] intelCancellationFuses = new byte[Integer.BYTES];
    private byte[] reservedSecond = new byte[12];
    private byte[] firmwareHash = new byte[COMMON_HASH_LEN];
    private byte[] romExtHash = new byte[COMMON_HASH_LEN];
    private byte[] deviceIdPublic = new byte[PUB_KEY_XY_LEN];
    private byte[][] enrollmentPublic = new byte[ATTESTATION_KEYS_ARRAY_SIZE][PUB_KEY_XY_LEN];
    private byte[] pufActivationHash = new byte[COMMON_HASH_LEN];
    private byte[] futureExpansion = new byte[0]; // dynamic
    private byte[] metalSigningKey = new byte[120];
    private byte[] metalSigningSig = new byte[112];
    private byte[] padding = new byte[0]; // dynamic

    // Used with Intel PUF Certificate Service Signing Key
    private byte[] ipcsSigLength = new byte[Integer.BYTES];
    private byte[] ipcsSignature = new byte[0];

    // Meta information
    private FlowType flowType = FlowType.FROM_DEVICE;

    public AttManifest withFlowType(FlowType flowType) {
        this.flowType = flowType;
        return this;
    }

    @Override
    public byte[] array() {
        final ByteBuffer buffer = ByteBuffer.allocate(AttManifestBuilder.BASIC_MANIFEST_LENGTH);

        buffer.put(magic);
        buffer.put(length);
        buffer.put(familyName);
        buffer.put(baseEdiId);
        buffer.put(familyIdentifier);
        buffer.put(manifestKeyOffset);
        buffer.put(deviceId);
        buffer.put(amsKeyId);
        buffer.put(reserved);
        buffer.put(efuseBlock);
        buffer.put(romPatchEfuseHash);
        buffer.put(intelCancellationFuses);
        buffer.put(reservedSecond);
        buffer.put(firmwareHash);
        buffer.put(romExtHash);
        buffer.put(deviceIdPublic);
        for (byte[] bytes : enrollmentPublic) {
            buffer.put(bytes);
        }
        buffer.put(pufActivationHash);
        buffer.put(futureExpansion);

        if (getFlowType() == FlowType.FROM_DEVICE) {
            buffer.put(metalSigningKey);
            buffer.put(metalSigningSig);
        } else {
            buffer.put(ipcsSigLength);
            buffer.put(ipcsSignature);
        }

        buffer.put(padding);

        return buffer.array();
    }

    public int getPayloadSignatureCapacity(int dynamicFieldsLength) {
        int capacity = 0;

        capacity += magic.length;
        capacity += length.length;
        capacity += familyName.length;
        capacity += Byte.BYTES; //baseEdiId;
        capacity += Byte.BYTES; //familyIdentifier
        capacity += manifestKeyOffset.length;
        capacity += deviceId.length;
        capacity += amsKeyId.length;
        capacity += reserved.length;
        capacity += efuseBlock.length;
        capacity += romPatchEfuseHash.length;
        capacity += intelCancellationFuses.length;
        capacity += reservedSecond.length;
        capacity += firmwareHash.length;
        capacity += romExtHash.length;
        capacity += deviceIdPublic.length;
        capacity += ATTESTATION_KEYS_ARRAY_SIZE * PUB_KEY_XY_LEN;
        capacity += pufActivationHash.length;

        if (getFlowType() == FlowType.FROM_DEVICE) {
            capacity += metalSigningKey.length;
        }

        capacity += dynamicFieldsLength;
        return capacity;
    }
}

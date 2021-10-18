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

package com.intel.bkp.ext.core.manufacturing;

import com.intel.bkp.ext.core.endianess.EndianessActor;
import com.intel.bkp.ext.core.endianess.EndianessStructureFields;
import com.intel.bkp.ext.core.endianess.EndianessStructureType;
import com.intel.bkp.ext.core.endianess.maps.AttManifestEndianessMapImpl;
import com.intel.bkp.ext.core.manufacturing.model.AttManifest;
import com.intel.bkp.ext.core.manufacturing.model.FlowType;
import com.intel.bkp.ext.core.psgcertificate.PsgDataBuilder;
import com.intel.bkp.ext.core.psgcertificate.PsgPublicKeyBuilder;
import com.intel.bkp.ext.core.psgcertificate.PsgSignatureBuilder;
import lombok.Getter;
import lombok.NoArgsConstructor;

import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;

@Getter
@NoArgsConstructor
public class AttManifestBuilder extends PsgDataBuilder<AttManifestBuilder> {

    public static final int MAGIC = 0x17629317;

    public static final String SHORT_NAME = "ATTMAN";

    public static final int BASIC_MANIFEST_LENGTH = 8188; // Basic attestation manifest capacity
    public static final int BASIC_MANIFEST_LENGTH_WITH_CRC = 8192; // Basic attestation manifest capacity in Aries 8kb
    public static final int MANIFEST_METAL_KEY_OFFSET = 3552;
    private final byte[] reserved = new byte[Integer.BYTES];
    private final byte[] reservedSecond = new byte[12];
    private FlowType flowType = FlowType.FROM_DEVICE;
    private Integer length = BASIC_MANIFEST_LENGTH_WITH_CRC;
    private String familyName;
    private byte baseEdiId;
    private byte familyIdentifier;
    private short manifestKeyOffset = 0;
    private byte[] deviceUniqueId = new byte[Long.BYTES];
    private byte[] amsKeyId = new byte[Integer.BYTES];
    private byte[] efuseBlock = new byte[AttManifest.EFUSE_BLOCK_LEN];
    private byte[] romPatchEfuseHash = new byte[AttManifest.COMMON_HASH_LEN];
    private byte[] intelCancellationFuses = new byte[Integer.BYTES];
    private byte[] firmwareHash = new byte[AttManifest.COMMON_HASH_LEN];
    private byte[] romExtHash = new byte[AttManifest.COMMON_HASH_LEN];
    private byte[] deviceIdPublic = new byte[AttManifest.PUB_KEY_XY_LEN];
    private byte[][] enrollmentPublic = new byte[AttManifest.ATTESTATION_KEYS_ARRAY_SIZE][AttManifest.PUB_KEY_XY_LEN];
    private byte[] pufActivationHash = new byte[AttManifest.COMMON_HASH_LEN];
    private byte[] futureExpansion = new byte[0];
    private PsgPublicKeyBuilder metalSigningKey;
    private PsgSignatureBuilder metalSigningSig;
    private byte[] padding = new byte[0];

    // Used with Intel PUF Certificate Service Signing Key
    private byte[] ipcsSigLength = new byte[Integer.BYTES];
    private byte[] ipcsSignature = new byte[0];

    @Override
    public EndianessStructureType currentStructureMap() {
        return EndianessStructureType.ATT_MANIFEST;
    }

    @Override
    public AttManifestBuilder withActor(EndianessActor actor) {
        changeActor(actor);
        return this;
    }

    @Override
    protected void initStructureMap(EndianessStructureType currentStructureType, EndianessActor currentActor) {
        maps.put(currentStructureType, new AttManifestEndianessMapImpl(currentActor));
    }
}

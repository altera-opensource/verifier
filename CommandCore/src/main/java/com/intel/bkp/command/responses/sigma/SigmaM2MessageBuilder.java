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

package com.intel.bkp.command.responses.sigma;

import com.intel.bkp.command.model.StructureType;
import com.intel.bkp.core.endianness.EndiannessActor;
import com.intel.bkp.core.endianness.StructureBuilder;
import com.intel.bkp.core.exceptions.ParseStructureException;
import com.intel.bkp.core.psgcertificate.PsgSignatureBuilder;
import com.intel.bkp.core.psgcertificate.model.PsgSignatureCurveType;
import com.intel.bkp.utils.ByteBufferSafe;
import lombok.Getter;
import lombok.Setter;

import java.nio.ByteBuffer;

import static com.intel.bkp.command.model.StructureField.SIGMA_M2_BKPS_DH_PUB_KEY;
import static com.intel.bkp.command.model.StructureField.SIGMA_M2_DEVICE_DH_PUB_KEY;
import static com.intel.bkp.command.model.StructureField.SIGMA_M2_DEVICE_UNIQUE_ID;
import static com.intel.bkp.command.model.StructureField.SIGMA_M2_MAC;
import static com.intel.bkp.command.model.StructureField.SIGMA_M2_MAGIC;
import static com.intel.bkp.command.model.StructureField.SIGMA_M2_PUBLIC_EFUSE_VALUES;
import static com.intel.bkp.command.model.StructureField.SIGMA_M2_RESERVED_HEADER;
import static com.intel.bkp.command.model.StructureField.SIGMA_M2_ROM_VERSION_NUM;
import static com.intel.bkp.command.model.StructureField.SIGMA_M2_SDM_FW_BUILD_ID;
import static com.intel.bkp.command.model.StructureField.SIGMA_M2_SDM_FW_SECURITY_VERSION_NUM;
import static com.intel.bkp.command.model.StructureField.SIGMA_M2_SDM_SESSION_ID;
import static com.intel.bkp.command.responses.sigma.DeviceFamilyFuseMap.S10;

/**
 * This class acts as an intermediate between FW and BKPS. It holds the data in raw form as received from FW. The
 * Builder can create and parse SigmaM2Message always converting it to the same data format.
 */
@Getter
@Setter
public class SigmaM2MessageBuilder
    extends StructureBuilder<SigmaM2MessageBuilder, SigmaM2Message> {

    private static final int M2_MAGIC_NUMBER = 0xFC06A385;
    public static final int SDM_FW_BUILD_ID_LEN = 28;
    public static final int DEVICE_FAMILY_FUSE_MAP_LEN = Byte.BYTES;
    public static final int RESERVED_LEN = 3;
    public static final int DH_PUB_KEY_LEN = 96;
    public static final int SHA_384_MAC_LEN = 48;

    private byte[] reservedHeader = new byte[Integer.BYTES];
    private byte[] magic = new byte[Integer.BYTES];
    private byte[] sdmSessionId = new byte[Integer.BYTES];
    private byte[] deviceUniqueId = new byte[Long.BYTES];
    private byte[] romVersionNum = new byte[Integer.BYTES];
    private byte[] sdmFwBuildId = new byte[SDM_FW_BUILD_ID_LEN];
    private byte[] sdmFwSecurityVersionNum = new byte[Integer.BYTES];
    private byte deviceFamilyFuseMap = S10.getByteFromOrdinal();
    private byte[] reserved = new byte[RESERVED_LEN];
    private byte[] publicEfuseValues = new byte[S10.getEfuseValuesFieldLen()];
    private byte[] deviceDhPubKey = new byte[DH_PUB_KEY_LEN];
    private byte[] bkpsDhPubKey = new byte[DH_PUB_KEY_LEN];
    private PsgSignatureBuilder signatureBuilder = PsgSignatureBuilder
        .empty(PsgSignatureCurveType.SECP384R1)
        .withActor(EndiannessActor.FIRMWARE);
    private byte[] mac = new byte[SHA_384_MAC_LEN];

    public SigmaM2MessageBuilder() {
        super(StructureType.SIGMA_M2);
    }

    @Override
    public SigmaM2Message build() {
        SigmaM2Message m2 = new SigmaM2Message();
        m2.setReservedHeader(convert(reservedHeader, SIGMA_M2_RESERVED_HEADER));
        m2.setMagic(convert(magic, SIGMA_M2_MAGIC));
        m2.setSdmSessionId(convert(sdmSessionId, SIGMA_M2_SDM_SESSION_ID));
        m2.setDeviceUniqueId(convert(deviceUniqueId, SIGMA_M2_DEVICE_UNIQUE_ID));
        m2.setRomVersionNum(convert(romVersionNum, SIGMA_M2_ROM_VERSION_NUM));
        m2.setSdmFwBuildId(convert(sdmFwBuildId, SIGMA_M2_SDM_FW_BUILD_ID));
        m2.setSdmFwSecurityVersionNum(convert(sdmFwSecurityVersionNum, SIGMA_M2_SDM_FW_SECURITY_VERSION_NUM));
        m2.setDeviceFamilyFuseMap(deviceFamilyFuseMap);
        m2.setReserved(reserved);
        m2.setPublicEfuseValues(convert(publicEfuseValues, SIGMA_M2_PUBLIC_EFUSE_VALUES));
        m2.setDeviceDhPubKey(convert(deviceDhPubKey, SIGMA_M2_DEVICE_DH_PUB_KEY));
        m2.setBkpsDhPubKey(convert(bkpsDhPubKey, SIGMA_M2_BKPS_DH_PUB_KEY));
        m2.setSignature(signatureBuilder.withActor(getActor()).build().array());
        m2.setMac(convert(mac, SIGMA_M2_MAC));

        return m2;
    }

    @Override
    public SigmaM2MessageBuilder self() {
        return this;
    }

    @Override
    public SigmaM2MessageBuilder parse(ByteBufferSafe buffer) throws ParseStructureException {
        buffer
            .get(reservedHeader)
            .get(magic)
            .get(sdmSessionId)
            .get(deviceUniqueId)
            .get(romVersionNum)
            .get(sdmFwBuildId)
            .get(sdmFwSecurityVersionNum);

        deviceFamilyFuseMap = buffer.getByte();
        publicEfuseValues = new DeviceFamilyFuseMapFactory(deviceFamilyFuseMap).get();

        buffer
            .get(reserved)
            .get(publicEfuseValues)
            .get(deviceDhPubKey)
            .get(bkpsDhPubKey);

        reservedHeader = convert(reservedHeader, SIGMA_M2_RESERVED_HEADER);
        magic = convert(magic, SIGMA_M2_MAGIC);
        sdmSessionId = convert(sdmSessionId, SIGMA_M2_SDM_SESSION_ID);
        deviceUniqueId = convert(deviceUniqueId, SIGMA_M2_DEVICE_UNIQUE_ID);
        romVersionNum = convert(romVersionNum, SIGMA_M2_ROM_VERSION_NUM);
        sdmFwBuildId = convert(sdmFwBuildId, SIGMA_M2_SDM_FW_BUILD_ID);
        sdmFwSecurityVersionNum = convert(sdmFwSecurityVersionNum, SIGMA_M2_SDM_FW_SECURITY_VERSION_NUM);
        publicEfuseValues = convert(publicEfuseValues, SIGMA_M2_PUBLIC_EFUSE_VALUES);
        deviceDhPubKey = convert(deviceDhPubKey, SIGMA_M2_DEVICE_DH_PUB_KEY);
        bkpsDhPubKey = convert(bkpsDhPubKey, SIGMA_M2_BKPS_DH_PUB_KEY);

        try {
            signatureBuilder.withActor(getActor()).parse(buffer);
        } catch (ParseStructureException e) {
            throw new ParseStructureException("Parsing signature from M2 failed.", e);
        }

        buffer.getAll(mac);
        mac = convert(mac, SIGMA_M2_MAC);

        return this;
    }

    /**
     * Returns data in the format required for verifying signature (as prepared by FW).
     */
    public byte[] getDataForSignature() {
        final int capacity = magic.length
            + sdmSessionId.length
            + deviceUniqueId.length
            + romVersionNum.length
            + sdmFwBuildId.length
            + sdmFwSecurityVersionNum.length
            + DEVICE_FAMILY_FUSE_MAP_LEN
            + reserved.length
            + publicEfuseValues.length
            + deviceDhPubKey.length
            + bkpsDhPubKey.length;

        return ByteBuffer.allocate(capacity)
            .put(convert(magic, SIGMA_M2_MAGIC))
            .put(convert(sdmSessionId, SIGMA_M2_SDM_SESSION_ID))
            .put(convert(deviceUniqueId, SIGMA_M2_DEVICE_UNIQUE_ID))
            .put(convert(romVersionNum, SIGMA_M2_ROM_VERSION_NUM))
            .put(convert(sdmFwBuildId, SIGMA_M2_SDM_FW_BUILD_ID))
            .put(convert(sdmFwSecurityVersionNum, SIGMA_M2_SDM_FW_SECURITY_VERSION_NUM))
            .put(deviceFamilyFuseMap)
            .put(reserved)
            .put(convert(publicEfuseValues, SIGMA_M2_PUBLIC_EFUSE_VALUES))
            .put(convert(deviceDhPubKey, SIGMA_M2_DEVICE_DH_PUB_KEY))
            .put(convert(bkpsDhPubKey, SIGMA_M2_BKPS_DH_PUB_KEY))
            .array();
    }

    /**
     * Returns data and signature in the format required for verifying MAC (as prepared by FW).
     */
    public byte[] getDataAndSignatureForMac() {
        byte[] dataForSignature = getDataForSignature();
        return ByteBuffer.allocate(dataForSignature.length + getSignatureLen())
            .put(dataForSignature)
            .put(signatureBuilder.withActor(getActor()).build().array())
            .array();
    }

    private int getSignatureLen() {
        return signatureBuilder.getTotalSignatureSize();
    }


}

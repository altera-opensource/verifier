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

import com.intel.bkp.core.endianness.EndiannessActor;
import com.intel.bkp.core.endianness.StructureBuilder;
import com.intel.bkp.core.exceptions.ParseStructureException;
import com.intel.bkp.core.psgcertificate.PsgSignatureBuilder;
import com.intel.bkp.core.psgcertificate.model.PsgSignatureCurveType;
import com.intel.bkp.utils.ByteBufferSafe;
import lombok.Getter;
import lombok.Setter;

import java.nio.ByteBuffer;

import static com.intel.bkp.command.model.StructureField.GET_MEASUREMENT_CMF_DESCRIPTOR_HASH;
import static com.intel.bkp.command.model.StructureField.GET_MEASUREMENT_DEVICE_DH_PUB_KEY;
import static com.intel.bkp.command.model.StructureField.GET_MEASUREMENT_DEVICE_UNIQUE_ID;
import static com.intel.bkp.command.model.StructureField.GET_MEASUREMENT_MAC;
import static com.intel.bkp.command.model.StructureField.GET_MEASUREMENT_MAGIC;
import static com.intel.bkp.command.model.StructureField.GET_MEASUREMENT_PUBLIC_EFUSE_VALUES;
import static com.intel.bkp.command.model.StructureField.GET_MEASUREMENT_RECORD_LEN;
import static com.intel.bkp.command.model.StructureField.GET_MEASUREMENT_ROM_VERSION_NUM;
import static com.intel.bkp.command.model.StructureField.GET_MEASUREMENT_SDM_FW_BUILD_ID;
import static com.intel.bkp.command.model.StructureField.GET_MEASUREMENT_SDM_FW_SECURITY_VERSION_NUM;
import static com.intel.bkp.command.model.StructureField.GET_MEASUREMENT_SDM_SESSION_ID;
import static com.intel.bkp.command.model.StructureField.GET_MEASUREMENT_VERIFIER_DH_PUB_KEY;
import static com.intel.bkp.command.model.StructureType.GET_MEASUREMENT_RSP;
import static com.intel.bkp.command.responses.sigma.DeviceFamilyFuseMap.S10;

@Getter
@Setter
public class GetMeasurementResponseBuilder
    extends StructureBuilder<GetMeasurementResponseBuilder, GetMeasurementResponse> {

    static final int SDM_FW_BUILD_ID_LEN = 28;
    static final int DEVICE_FAMILY_FUSE_MAP_LEN = Byte.BYTES;
    static final int RESERVED_LEN = 3;
    static final int DH_PUB_KEY_LEN = 96;
    static final int CMF_DESCRIPTOR_HASH_LEN = 48;
    static final int RESERVED2_LEN = 12;
    static final int NO_OF_MEASUREMENT_BLOCK_LEN = Byte.BYTES;
    static final int RESERVED3_LEN = Byte.BYTES;
    static final int MEASUREMENT_RECORD_SIZE_LEN = Short.BYTES;
    static final int SHA_384_MAC_LEN = 48;

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
    private byte[] verifierDhPubKey = new byte[DH_PUB_KEY_LEN];
    private byte[] cmfDescriptorHash = new byte[CMF_DESCRIPTOR_HASH_LEN];
    private byte[] reserved2 = new byte[RESERVED2_LEN];
    private byte numberOfMeasurementBlocks = 0;
    private byte reserved3 = 0;
    private short measurementRecordLen = 0;
    private byte[] measurementRecord = new byte[0];
    private PsgSignatureBuilder signatureBuilder = PsgSignatureBuilder
        .empty(PsgSignatureCurveType.SECP384R1)
        .withActor(EndiannessActor.FIRMWARE);
    private byte[] mac = new byte[SHA_384_MAC_LEN];

    public GetMeasurementResponseBuilder() {
        super(GET_MEASUREMENT_RSP);
    }

    @Override
    public GetMeasurementResponseBuilder self() {
        return this;
    }

    @Override
    public GetMeasurementResponse build() {
        final GetMeasurementResponse response = new GetMeasurementResponse();
        response.setReservedHeader(reservedHeader);
        response.setMagic(convert(magic, GET_MEASUREMENT_MAGIC));
        response.setSdmSessionId(convert(sdmSessionId, GET_MEASUREMENT_SDM_SESSION_ID));
        response.setDeviceUniqueId(convert(deviceUniqueId, GET_MEASUREMENT_DEVICE_UNIQUE_ID));
        response.setRomVersionNum(convert(romVersionNum, GET_MEASUREMENT_ROM_VERSION_NUM));
        response.setSdmFwBuildId(convert(sdmFwBuildId, GET_MEASUREMENT_SDM_FW_BUILD_ID));
        response.setSdmFwSecurityVersionNum(
            convert(sdmFwSecurityVersionNum, GET_MEASUREMENT_SDM_FW_SECURITY_VERSION_NUM));
        response.setDeviceFamilyFuseMap(deviceFamilyFuseMap);
        response.setReserved(reserved);
        response.setPublicEfuseValues(convert(publicEfuseValues, GET_MEASUREMENT_PUBLIC_EFUSE_VALUES));
        response.setDeviceDhPubKey(convert(deviceDhPubKey, GET_MEASUREMENT_DEVICE_DH_PUB_KEY));
        response.setVerifierDhPubKey(convert(verifierDhPubKey, GET_MEASUREMENT_VERIFIER_DH_PUB_KEY));
        response.setCmfDescriptorHash(convert(cmfDescriptorHash, GET_MEASUREMENT_CMF_DESCRIPTOR_HASH));
        response.setReserved2(reserved2);
        response.setNumberOfMeasurementBlocks(numberOfMeasurementBlocks);
        response.setReserved3(reserved3);
        response.setMeasurementRecordLen(convertShort(measurementRecordLen, GET_MEASUREMENT_RECORD_LEN));
        response.setMeasurementRecord(measurementRecord);
        response.setSignature(signatureBuilder.withActor(getActor()).build().array());
        response.setMac(convert(mac, GET_MEASUREMENT_MAC));
        return response;
    }

    @Override
    public GetMeasurementResponseBuilder parse(ByteBufferSafe buffer) {
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
            .get(verifierDhPubKey)
            .get(cmfDescriptorHash)
            .get(reserved2);
        numberOfMeasurementBlocks = buffer.getByte();
        reserved3 = buffer.getByte();
        measurementRecordLen = buffer.getShort();

        magic = convert(magic, GET_MEASUREMENT_MAGIC);
        sdmSessionId = convert(sdmSessionId, GET_MEASUREMENT_SDM_SESSION_ID);
        deviceUniqueId = convert(deviceUniqueId, GET_MEASUREMENT_DEVICE_UNIQUE_ID);
        romVersionNum = convert(romVersionNum, GET_MEASUREMENT_ROM_VERSION_NUM);
        sdmFwBuildId = convert(sdmFwBuildId, GET_MEASUREMENT_SDM_FW_BUILD_ID);
        sdmFwSecurityVersionNum = convert(sdmFwSecurityVersionNum,
            GET_MEASUREMENT_SDM_FW_SECURITY_VERSION_NUM);
        publicEfuseValues = convert(publicEfuseValues, GET_MEASUREMENT_PUBLIC_EFUSE_VALUES);
        deviceDhPubKey = convert(deviceDhPubKey, GET_MEASUREMENT_DEVICE_DH_PUB_KEY);
        verifierDhPubKey = convert(verifierDhPubKey, GET_MEASUREMENT_VERIFIER_DH_PUB_KEY);
        cmfDescriptorHash = convert(cmfDescriptorHash, GET_MEASUREMENT_CMF_DESCRIPTOR_HASH);
        measurementRecordLen = convertShort(measurementRecordLen, GET_MEASUREMENT_RECORD_LEN);

        measurementRecord = buffer.arrayFromShort(measurementRecordLen);
        buffer.get(measurementRecord);

        try {
            signatureBuilder.withActor(getActor()).parse(buffer);
        } catch (ParseStructureException e) {
            throw new RuntimeException("Parsing signature from GET_MEASUREMENT_RSP failed.", e);
        }

        buffer.getAll(mac);
        mac = convert(mac, GET_MEASUREMENT_MAC);

        return this;
    }

    public byte[] getDataForSignature() {
        int capacity = magic.length
            + sdmSessionId.length
            + deviceUniqueId.length
            + romVersionNum.length
            + sdmFwBuildId.length
            + sdmFwSecurityVersionNum.length
            + DEVICE_FAMILY_FUSE_MAP_LEN
            + reserved.length
            + publicEfuseValues.length
            + deviceDhPubKey.length
            + verifierDhPubKey.length
            + cmfDescriptorHash.length
            + reserved2.length
            + NO_OF_MEASUREMENT_BLOCK_LEN
            + RESERVED3_LEN
            + MEASUREMENT_RECORD_SIZE_LEN
            + measurementRecord.length;

        return ByteBuffer.allocate(capacity)
            .put(convert(magic, GET_MEASUREMENT_MAGIC))
            .put(convert(sdmSessionId, GET_MEASUREMENT_SDM_SESSION_ID))
            .put(convert(deviceUniqueId, GET_MEASUREMENT_DEVICE_UNIQUE_ID))
            .put(convert(romVersionNum, GET_MEASUREMENT_ROM_VERSION_NUM))
            .put(convert(sdmFwBuildId, GET_MEASUREMENT_SDM_FW_BUILD_ID))
            .put(
                convert(sdmFwSecurityVersionNum, GET_MEASUREMENT_SDM_FW_SECURITY_VERSION_NUM))
            .put(deviceFamilyFuseMap)
            .put(reserved)
            .put(convert(publicEfuseValues, GET_MEASUREMENT_PUBLIC_EFUSE_VALUES))
            .put(convert(deviceDhPubKey, GET_MEASUREMENT_DEVICE_DH_PUB_KEY))
            .put(convert(verifierDhPubKey, GET_MEASUREMENT_VERIFIER_DH_PUB_KEY))
            .put(convert(cmfDescriptorHash, GET_MEASUREMENT_CMF_DESCRIPTOR_HASH))
            .put(reserved2)
            .put(numberOfMeasurementBlocks)
            .put(reserved3)
            .putShort(convertShort(measurementRecordLen, GET_MEASUREMENT_RECORD_LEN))
            .put(measurementRecord)
            .array();
    }
}

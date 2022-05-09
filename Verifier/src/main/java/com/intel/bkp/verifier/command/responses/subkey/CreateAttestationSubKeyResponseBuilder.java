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

package com.intel.bkp.verifier.command.responses.subkey;

import com.intel.bkp.core.endianess.EndianessActor;
import com.intel.bkp.core.psgcertificate.PsgPublicKeyBuilder;
import com.intel.bkp.core.psgcertificate.PsgSignatureBuilder;
import com.intel.bkp.core.psgcertificate.exceptions.PsgCertificateException;
import com.intel.bkp.core.psgcertificate.exceptions.PsgInvalidSignatureException;
import com.intel.bkp.utils.ByteBufferSafe;
import com.intel.bkp.verifier.command.maps.CreateSubKeyRspEndianessMapImpl;
import com.intel.bkp.verifier.command.responses.BaseResponseBuilder;
import com.intel.bkp.verifier.endianess.EndianessStructureFields;
import com.intel.bkp.verifier.endianess.EndianessStructureType;
import com.intel.bkp.verifier.exceptions.SigmaException;
import lombok.Getter;
import lombok.Setter;

import java.nio.ByteBuffer;

@Getter
@Setter
public class CreateAttestationSubKeyResponseBuilder
    extends BaseResponseBuilder<CreateAttestationSubKeyResponseBuilder> {

    static final int SDM_FW_BUILD_ID_LEN = 28;
    static final int RESERVED_LEN = 4;
    static final int PUB_EFUSE_VALUES_LEN = 256;
    static final int DH_PUB_KEY_LEN = 96;
    static final int SHA_384_MAC_LEN = 48;
    private static final int CONTEXT_LEN = 28;
    private static final int COUNTER_LEN = Integer.BYTES;

    private byte[] reservedHeader = new byte[Integer.BYTES];
    private byte[] magic = new byte[Integer.BYTES];
    private byte[] sdmSessionId = new byte[Integer.BYTES];
    private byte[] deviceUniqueId = new byte[Long.BYTES];
    private byte[] romVersionNum = new byte[Integer.BYTES];
    private byte[] sdmFwBuildId = new byte[SDM_FW_BUILD_ID_LEN];
    private byte[] sdmFwSecurityVersionNum = new byte[Integer.BYTES];
    private byte[] reserved = new byte[RESERVED_LEN];
    private byte[] publicEfuseValues = new byte[PUB_EFUSE_VALUES_LEN];
    private byte[] deviceDhPubKey = new byte[DH_PUB_KEY_LEN];
    private byte[] verifierDhPubKey = new byte[DH_PUB_KEY_LEN];
    private byte[] verifierInputContext = new byte[CONTEXT_LEN];
    private byte[] verifierCounter = new byte[COUNTER_LEN];
    private PsgPublicKeyBuilder publicKeyBuilder = new PsgPublicKeyBuilder().withActor(EndianessActor.FIRMWARE);
    private PsgSignatureBuilder signatureBuilder = new PsgSignatureBuilder().withActor(EndianessActor.FIRMWARE);
    private byte[] mac = new byte[SHA_384_MAC_LEN];

    @Override
    public EndianessStructureType currentStructureMap() {
        return EndianessStructureType.CREATE_ATTESTATION_SUBKEY_RSP;
    }

    @Override
    public CreateAttestationSubKeyResponseBuilder withActor(EndianessActor actor) {
        changeActor(actor);
        return this;
    }

    @Override
    public void initStructureMap(EndianessStructureType currentStructureType, EndianessActor currentActor) {
        maps.put(currentStructureType, new CreateSubKeyRspEndianessMapImpl(currentActor));
    }

    public CreateAttestationSubKeyResponse build() {
        final CreateAttestationSubKeyResponse response = new CreateAttestationSubKeyResponse();
        response.setReservedHeader(convert(reservedHeader, EndianessStructureFields.SUBKEY_RESERVED_HEADER));
        response.setMagic(convert(magic, EndianessStructureFields.SUBKEY_MAGIC));
        response.setSdmSessionId(convert(sdmSessionId, EndianessStructureFields.SUBKEY_SDM_SESSION_ID));
        response.setDeviceUniqueId(convert(deviceUniqueId, EndianessStructureFields.SUBKEY_DEVICE_UNIQUE_ID));
        response.setRomVersionNum(convert(romVersionNum, EndianessStructureFields.SUBKEY_ROM_VERSION_NUM));
        response.setSdmFwBuildId(convert(sdmFwBuildId, EndianessStructureFields.SUBKEY_SDM_FW_BUILD_ID));
        response.setSdmFwSecurityVersionNum(convert(sdmFwSecurityVersionNum,
            EndianessStructureFields.SUBKEY_SDM_FW_SECURITY_VERSION_NUM));
        response.setReserved(convert(reserved, EndianessStructureFields.SUBKEY_RESERVED));
        response
            .setPublicEfuseValues(convert(publicEfuseValues, EndianessStructureFields.SUBKEY_PUBLIC_EFUSE_VALUES));
        response.setDeviceDhPubKey(convert(deviceDhPubKey, EndianessStructureFields.SUBKEY_DEVICE_DH_PUB_KEY));
        response
            .setVerifierDhPubKey(convert(verifierDhPubKey, EndianessStructureFields.SUBKEY_VERIFIER_DH_PUB_KEY));
        response.setVerifierInputContext(convert(verifierInputContext, EndianessStructureFields.SUBKEY_CONTEXT));
        response.setVerifierCounter(convert(verifierCounter, EndianessStructureFields.SUBKEY_COUNTER));
        response.setAttestationPublicKey(publicKeyBuilder.withActor(getActor()).build().array());
        response.setSignature(signatureBuilder.withActor(getActor()).build().array());
        response.setMac(convert(mac, EndianessStructureFields.SUBKEY_MAC));
        return response;
    }

    public CreateAttestationSubKeyResponseBuilder parse(byte[] message) {
        ByteBufferSafe buffer = ByteBufferSafe.wrap(message);
        buffer
            .get(reservedHeader)
            .get(magic)
            .get(sdmSessionId)
            .get(deviceUniqueId)
            .get(romVersionNum)
            .get(sdmFwBuildId)
            .get(sdmFwSecurityVersionNum)
            .get(reserved)
            .get(publicEfuseValues)
            .get(deviceDhPubKey)
            .get(verifierDhPubKey)
            .get(verifierInputContext)
            .get(verifierCounter);

        reservedHeader = convert(reservedHeader, EndianessStructureFields.SUBKEY_RESERVED_HEADER);
        magic = convert(magic, EndianessStructureFields.SUBKEY_MAGIC);
        sdmSessionId = convert(sdmSessionId, EndianessStructureFields.SUBKEY_SDM_SESSION_ID);
        deviceUniqueId = convert(deviceUniqueId, EndianessStructureFields.SUBKEY_DEVICE_UNIQUE_ID);
        romVersionNum = convert(romVersionNum, EndianessStructureFields.SUBKEY_ROM_VERSION_NUM);
        sdmFwBuildId = convert(sdmFwBuildId, EndianessStructureFields.SUBKEY_SDM_FW_BUILD_ID);
        sdmFwSecurityVersionNum = convert(sdmFwSecurityVersionNum,
            EndianessStructureFields.SUBKEY_SDM_FW_SECURITY_VERSION_NUM);
        reserved = convert(reserved, EndianessStructureFields.SUBKEY_RESERVED);
        publicEfuseValues = convert(publicEfuseValues, EndianessStructureFields.SUBKEY_PUBLIC_EFUSE_VALUES);
        deviceDhPubKey = convert(deviceDhPubKey, EndianessStructureFields.SUBKEY_DEVICE_DH_PUB_KEY);
        verifierDhPubKey = convert(verifierDhPubKey, EndianessStructureFields.SUBKEY_VERIFIER_DH_PUB_KEY);
        verifierInputContext = convert(verifierInputContext, EndianessStructureFields.SUBKEY_CONTEXT);
        verifierCounter = convert(verifierCounter, EndianessStructureFields.SUBKEY_COUNTER);

        try {
            publicKeyBuilder.withActor(getActor()).parse(buffer);
            signatureBuilder.withActor(getActor()).parse(buffer);
        } catch (PsgInvalidSignatureException e) {
            throw new SigmaException("Parsing signature from CREATE_ATTESTATION_SUBKEY_RSP failed.", e);
        } catch (PsgCertificateException e) {
            throw new SigmaException("Parsing public key from CREATE_ATTESTATION_SUBKEY_RSP failed.", e);
        }

        buffer.getAll(mac);
        mac = convert(mac, EndianessStructureFields.SUBKEY_MAC);

        return this;
    }

    public byte[] getDataForSignature() {
        int capacity =
            magic.length
                + sdmSessionId.length
                + deviceUniqueId.length
                + romVersionNum.length
                + sdmFwBuildId.length
                + sdmFwSecurityVersionNum.length + reserved.length
                + publicEfuseValues.length
                + deviceDhPubKey.length
                + verifierDhPubKey.length
                + verifierInputContext.length
                + verifierCounter.length;

        byte[] attestationPublicKey = publicKeyBuilder.withActor(getActor()).build().array();
        capacity += attestationPublicKey.length;

        return ByteBuffer.allocate(capacity)
            .put(convert(magic, EndianessStructureFields.SUBKEY_MAGIC))
            .put(convert(sdmSessionId, EndianessStructureFields.SUBKEY_SDM_SESSION_ID))
            .put(convert(deviceUniqueId, EndianessStructureFields.SUBKEY_DEVICE_UNIQUE_ID))
            .put(convert(romVersionNum, EndianessStructureFields.SUBKEY_ROM_VERSION_NUM))
            .put(convert(sdmFwBuildId, EndianessStructureFields.SUBKEY_SDM_FW_BUILD_ID))
            .put(convert(sdmFwSecurityVersionNum, EndianessStructureFields.SUBKEY_SDM_FW_SECURITY_VERSION_NUM))
            .put(convert(reserved, EndianessStructureFields.SUBKEY_RESERVED))
            .put(convert(publicEfuseValues, EndianessStructureFields.SUBKEY_PUBLIC_EFUSE_VALUES))
            .put(convert(deviceDhPubKey, EndianessStructureFields.SUBKEY_DEVICE_DH_PUB_KEY))
            .put(convert(verifierDhPubKey, EndianessStructureFields.SUBKEY_VERIFIER_DH_PUB_KEY))
            .put(convert(verifierInputContext, EndianessStructureFields.SUBKEY_CONTEXT))
            .put(convert(verifierCounter, EndianessStructureFields.SUBKEY_COUNTER))
            .put(attestationPublicKey)
            .array();
    }
}

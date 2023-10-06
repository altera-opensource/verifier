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

import com.intel.bkp.command.logger.ILogger;
import com.intel.bkp.command.model.Response;
import com.intel.bkp.core.interfaces.IStructure;
import lombok.Getter;
import lombok.Setter;

import java.nio.ByteBuffer;

@Getter
@Setter
public class CreateAttestationSubKeyResponse implements Response, ILogger, IStructure {

    private byte[] reservedHeader = new byte[0];
    private byte[] magic = new byte[0];
    private byte[] sdmSessionId = new byte[0];
    private byte[] deviceUniqueId = new byte[0];
    private byte[] romVersionNum = new byte[0];
    private byte[] sdmFwBuildId = new byte[0];
    private byte[] sdmFwSecurityVersionNum = new byte[0];
    private byte[] reserved = new byte[0];
    private byte[] publicEfuseValues = new byte[0];
    private byte[] deviceDhPubKey = new byte[0];
    private byte[] verifierDhPubKey = new byte[0];
    private byte[] verifierInputContext = new byte[0];
    private byte[] verifierCounter = new byte[0];
    private byte[] attestationPublicKey = new byte[0];
    private byte[] signature = new byte[0];
    private byte[] mac = new byte[0];

    @Override
    public byte[] array() {
        return ByteBuffer.allocate(
            reservedHeader.length
                + magic.length
                + sdmSessionId.length
                + deviceUniqueId.length
                + romVersionNum.length
                + sdmFwBuildId.length
                + sdmFwSecurityVersionNum.length
                + reserved.length
                + publicEfuseValues.length
                + deviceDhPubKey.length
                + verifierDhPubKey.length
                + verifierInputContext.length
                + verifierCounter.length
                + attestationPublicKey.length
                + signature.length
                + mac.length)
            .put(reservedHeader)
            .put(magic)
            .put(sdmSessionId)
            .put(deviceUniqueId)
            .put(romVersionNum)
            .put(sdmFwBuildId)
            .put(sdmFwSecurityVersionNum)
            .put(reserved)
            .put(publicEfuseValues)
            .put(deviceDhPubKey)
            .put(verifierDhPubKey)
            .put(verifierInputContext)
            .put(verifierCounter)
            .put(attestationPublicKey)
            .put(signature)
            .put(mac)
            .array();
    }
}

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

package com.intel.bkp.verifier.service.measurements;

import com.intel.bkp.core.manufacturing.model.PufType;
import com.intel.bkp.crypto.CryptoUtils;
import com.intel.bkp.crypto.exceptions.EcdhKeyPairException;
import com.intel.bkp.verifier.database.model.S10CacheEntity;
import com.intel.bkp.verifier.exceptions.SigmaException;
import com.intel.bkp.verifier.model.RootChainType;
import lombok.AccessLevel;
import lombok.Getter;
import lombok.RequiredArgsConstructor;

import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;

import static com.intel.bkp.crypto.constants.CryptoConstants.EC_CURVE_SPEC_384;
import static com.intel.bkp.crypto.constants.CryptoConstants.EC_KEY;
import static com.intel.bkp.utils.HexConverter.fromHex;

@Getter
@RequiredArgsConstructor(access = AccessLevel.PACKAGE)
public class GpDeviceMeasurementsRequest {

    private final byte[] deviceId;
    private final RootChainType chainType;
    private final PublicKey aliasPubKey;
    private final PufType pufType;
    private final String context;
    private final int counter;

    public static GpDeviceMeasurementsRequest forDice(byte[] deviceId, PublicKey aliasPubKey, PufType pufType) {
        return new GpDeviceMeasurementsRequest(deviceId, RootChainType.MULTI, aliasPubKey, pufType, "", 0);
    }

    public static GpDeviceMeasurementsRequest forS10(byte[] deviceId, S10CacheEntity entity) {
        final var aliasPubKey = getPublicKey(entity);
        final var pufType = PufType.valueOf(entity.getPufType());
        return new GpDeviceMeasurementsRequest(deviceId, RootChainType.SINGLE, aliasPubKey, pufType,
            entity.getContext(), entity.getCounter());
    }

    private static PublicKey getPublicKey(S10CacheEntity entity) {
        try {
            final String pubKeyXY = entity.getAlias();
            return CryptoUtils.toEcPublicBC(fromHex(pubKeyXY), EC_KEY, EC_CURVE_SPEC_384);
        } catch (NoSuchAlgorithmException | InvalidKeySpecException | EcdhKeyPairException e) {
            throw new SigmaException("Failed to recover PublicKey from alias.", e);
        }
    }
}

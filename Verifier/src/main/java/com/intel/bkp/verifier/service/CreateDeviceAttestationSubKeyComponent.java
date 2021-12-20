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

package com.intel.bkp.verifier.service;

import com.intel.bkp.ext.core.endianess.EndianessActor;
import com.intel.bkp.ext.core.manufacturing.model.PufType;
import com.intel.bkp.ext.core.psgcertificate.model.PsgPublicKey;
import com.intel.bkp.ext.crypto.ecdh.EcdhKeyPair;
import com.intel.bkp.ext.crypto.exceptions.EcdhKeyPairException;
import com.intel.bkp.ext.utils.HexConverter;
import com.intel.bkp.verifier.command.responses.subkey.CreateAttestationSubKeyResponse;
import com.intel.bkp.verifier.command.responses.subkey.CreateAttestationSubKeyResponseBuilder;
import com.intel.bkp.verifier.database.model.S10CacheEntity;
import com.intel.bkp.verifier.exceptions.InternalLibraryException;
import com.intel.bkp.verifier.exceptions.UnknownCommandException;
import com.intel.bkp.verifier.model.VerifierExchangeResponse;
import com.intel.bkp.verifier.service.certificate.AppContext;
import com.intel.bkp.verifier.service.certificate.S10AttestationRevocationService;
import com.intel.bkp.verifier.service.sender.CreateAttestationSubKeyMessageSender;
import com.intel.bkp.verifier.service.sender.TeardownMessageSender;
import com.intel.bkp.verifier.sigma.CreateAttestationSubKeyVerifier;
import com.intel.bkp.verifier.sigma.SigmaM2DeviceIdVerifier;
import lombok.AccessLevel;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;

import java.nio.ByteBuffer;
import java.security.PublicKey;
import java.security.SecureRandom;

@Slf4j
@RequiredArgsConstructor(access = AccessLevel.PACKAGE)
public class CreateDeviceAttestationSubKeyComponent {

    private final CreateAttestationSubKeyMessageSender createSubKeyMessageSender;
    private final TeardownMessageSender teardownMessageSender;
    private final CreateAttestationSubKeyVerifier createSubKeyVerifier;
    private final S10AttestationRevocationService s10AttestationRevocationService;
    private final SigmaM2DeviceIdVerifier deviceIdVerifier;

    public CreateDeviceAttestationSubKeyComponent() {
        this(new CreateAttestationSubKeyMessageSender(),
            new TeardownMessageSender(),
            new CreateAttestationSubKeyVerifier(),
            new S10AttestationRevocationService(),
            new SigmaM2DeviceIdVerifier()
        );
    }

    public VerifierExchangeResponse perform(String context, PufType pufType, byte[] deviceId) {

        return perform(AppContext.instance(), context, pufType, deviceId);
    }

    VerifierExchangeResponse perform(AppContext appContext, String context, PufType pufType, byte[] deviceId) {

        final EcdhKeyPair serviceDhKeyPair = generateEcdhKeyPair();
        final int counter = new SecureRandom().nextInt();
        final CreateAttestationSubKeyResponseBuilder subKeyResponseBuilder;

        try {
            subKeyResponseBuilder = createSubKeyMessageSender.send(appContext.getTransportLayer(),
                appContext.getCommandLayer(), context, counter, pufType, serviceDhKeyPair);
        } catch (UnknownCommandException e) {
            log.error("This is FM/DM board - CreateAttestationSubKey command is not supported.");
            return VerifierExchangeResponse.ERROR;
        }

        final CreateAttestationSubKeyResponse response = subKeyResponseBuilder
            .withActor(EndianessActor.SERVICE)
            .build();

        final PublicKey pufAttestationPubKey = s10AttestationRevocationService.checkAndRetrieve(deviceId,
            PufType.getPufTypeHex(pufType));

        deviceIdVerifier.verify(deviceId, response.getDeviceUniqueId());
        createSubKeyVerifier.verify(response, serviceDhKeyPair, pufAttestationPubKey);
        teardownMessageSender.send(appContext.getTransportLayer(),
            appContext.getCommandLayer(), response.getSdmSessionId());
        createEntityInDatabase(appContext, deviceId, context, counter, pufType, subKeyResponseBuilder);
        return VerifierExchangeResponse.OK;
    }

    private EcdhKeyPair generateEcdhKeyPair() {
        try {
            return EcdhKeyPair.generate();
        } catch (EcdhKeyPairException e) {
            throw new InternalLibraryException("Failed to generate ECDH keypair.", e);
        }
    }

    private byte[] getAttestationSubKeyXY(CreateAttestationSubKeyResponseBuilder responseBuilder) {
        final PsgPublicKey attestationSubKey = responseBuilder
            .getPublicKeyBuilder()
            .withActor(EndianessActor.SERVICE)
            .build();
        final byte[] pointX = attestationSubKey.getPointX();
        final byte[] pointY = attestationSubKey.getPointY();
        return ByteBuffer.allocate(pointX.length + pointY.length)
            .put(pointX)
            .put(pointY)
            .array();
    }

    private void createEntityInDatabase(AppContext appContext, byte[] deviceId, String context, int counter,
        PufType pufType, CreateAttestationSubKeyResponseBuilder subKeyResponseBuilder) {
        appContext
            .getSqLiteHelper()
            .getS10CacheEntityService()
            .store(
                new S10CacheEntity(HexConverter.toHex(deviceId), context, counter, pufType.name(),
                    HexConverter.toHex(getAttestationSubKeyXY(subKeyResponseBuilder)))
            );
    }
}

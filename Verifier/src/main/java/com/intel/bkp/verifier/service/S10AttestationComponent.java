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

import com.intel.bkp.ext.core.manufacturing.model.PufType;
import com.intel.bkp.ext.crypto.ecdh.EcdhKeyPair;
import com.intel.bkp.ext.crypto.exceptions.EcdhKeyPairException;
import com.intel.bkp.verifier.command.responses.attestation.GetMeasurementResponse;
import com.intel.bkp.verifier.command.responses.attestation.GetMeasurementResponseToTcbInfoMapper;
import com.intel.bkp.verifier.database.model.S10CacheEntity;
import com.intel.bkp.verifier.exceptions.CacheEntityDoesNotExistException;
import com.intel.bkp.verifier.exceptions.InternalLibraryException;
import com.intel.bkp.verifier.interfaces.CommandLayer;
import com.intel.bkp.verifier.interfaces.TransportLayer;
import com.intel.bkp.verifier.model.VerifierExchangeResponse;
import com.intel.bkp.verifier.model.dice.TcbInfoAggregator;
import com.intel.bkp.verifier.service.certificate.AppContext;
import com.intel.bkp.verifier.service.certificate.S10AttestationRevocationService;
import com.intel.bkp.verifier.service.measurements.EvidenceVerifier;
import com.intel.bkp.verifier.service.sender.GetMeasurementMessageSender;
import com.intel.bkp.verifier.service.sender.TeardownMessageSender;
import com.intel.bkp.verifier.sigma.GetMeasurementVerifier;
import com.intel.bkp.verifier.sigma.SigmaM2DeviceIdVerifier;
import lombok.AccessLevel;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;

import java.util.Optional;

@Slf4j
@RequiredArgsConstructor(access = AccessLevel.PACKAGE)
public class S10AttestationComponent {

    private final GetMeasurementResponseToTcbInfoMapper measurementMapper;
    private final GetMeasurementMessageSender getMeasurementMessageSender;
    private final TeardownMessageSender teardownMessageSender;
    private final GetMeasurementVerifier getMeasurementVerifier;
    private final EvidenceVerifier evidenceVerifier;
    private final S10AttestationRevocationService s10AttestationRevocationService;
    private final SigmaM2DeviceIdVerifier deviceIdVerifier;
    private final TcbInfoAggregator tcbInfoAggregator;

    public S10AttestationComponent() {
        this(new GetMeasurementResponseToTcbInfoMapper(), new GetMeasurementMessageSender(),
            new TeardownMessageSender(), new GetMeasurementVerifier(), new EvidenceVerifier(),
            new S10AttestationRevocationService(), new SigmaM2DeviceIdVerifier(), new TcbInfoAggregator());
    }

    public VerifierExchangeResponse perform(String refMeasurement, byte[] deviceId) {
        return perform(AppContext.instance(), refMeasurement, deviceId);
    }

    VerifierExchangeResponse perform(AppContext appContext, String refMeasurement, byte[] deviceId) {

        final TransportLayer transportLayer = appContext.getTransportLayer();
        final CommandLayer commandLayer = appContext.getCommandLayer();

        final S10CacheEntity entity = readEntityFromDatabase(appContext, deviceId);

        s10AttestationRevocationService.checkAndRetrieve(deviceId, PufType.getPufTypeHex(entity.getPufType()));

        final EcdhKeyPair serviceDhKeyPair = generateEcdhKeyPair();
        final GetMeasurementResponse response =
            getMeasurementMessageSender.send(transportLayer, commandLayer, serviceDhKeyPair, entity);
        getMeasurementVerifier.verify(response, serviceDhKeyPair, entity);

        deviceIdVerifier.verify(deviceId, response.getDeviceUniqueId());
        teardownMessageSender.send(transportLayer, commandLayer, response.getSdmSessionId());

        tcbInfoAggregator.add(measurementMapper.map(response));

        return evidenceVerifier.verify(tcbInfoAggregator, refMeasurement);
    }

    private S10CacheEntity readEntityFromDatabase(AppContext appContext, byte[] deviceId) {
        final Optional<S10CacheEntity> entity = appContext
            .getSqLiteHelper()
            .getS10CacheEntityService()
            .read(deviceId);

        return entity.orElseThrow(CacheEntityDoesNotExistException::new);
    }

    private EcdhKeyPair generateEcdhKeyPair() {
        try {
            return EcdhKeyPair.generate();
        } catch (EcdhKeyPairException e) {
            throw new InternalLibraryException("Failed to generate ECDH keypair.", e);
        }
    }
}

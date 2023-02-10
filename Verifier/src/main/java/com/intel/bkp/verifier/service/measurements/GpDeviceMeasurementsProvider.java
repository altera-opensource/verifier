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

package com.intel.bkp.verifier.service.measurements;

import com.intel.bkp.crypto.ecdh.EcdhKeyPair;
import com.intel.bkp.crypto.exceptions.EcdhKeyPairException;
import com.intel.bkp.fpgacerts.dice.tcbinfo.TcbInfoMeasurement;
import com.intel.bkp.verifier.command.responses.attestation.GetMeasurementResponse;
import com.intel.bkp.verifier.command.responses.attestation.GpMeasurementResponseToTcbInfoMapper;
import com.intel.bkp.verifier.exceptions.InternalLibraryException;
import com.intel.bkp.verifier.interfaces.CommandLayer;
import com.intel.bkp.verifier.interfaces.IDeviceMeasurementsProvider;
import com.intel.bkp.verifier.interfaces.IMeasurementResponseToTcbInfoMapper;
import com.intel.bkp.verifier.interfaces.TransportLayer;
import com.intel.bkp.verifier.service.certificate.AppContext;
import com.intel.bkp.verifier.service.sender.GetMeasurementMessageSender;
import com.intel.bkp.verifier.service.sender.TeardownMessageSender;
import com.intel.bkp.verifier.sigma.GetMeasurementVerifier;
import com.intel.bkp.verifier.sigma.SigmaM2DeviceIdVerifier;
import lombok.RequiredArgsConstructor;

import java.security.PublicKey;
import java.util.List;

@RequiredArgsConstructor
public class GpDeviceMeasurementsProvider implements IDeviceMeasurementsProvider<GpDeviceMeasurementsRequest> {

    private final TransportLayer transportLayer;
    private final CommandLayer commandLayer;
    private final GetMeasurementMessageSender getMeasurementMessageSender;
    private final TeardownMessageSender teardownMessageSender;
    private final GetMeasurementVerifier getMeasurementVerifier;
    private final SigmaM2DeviceIdVerifier deviceIdVerifier;
    private final IMeasurementResponseToTcbInfoMapper<GetMeasurementResponse> measurementResponseMapper;

    public GpDeviceMeasurementsProvider() {
        this(AppContext.instance());
    }

    GpDeviceMeasurementsProvider(AppContext appContext) {
        this(appContext.getTransportLayer(), appContext.getCommandLayer(), new GetMeasurementMessageSender(),
            new TeardownMessageSender(), new GetMeasurementVerifier(), new SigmaM2DeviceIdVerifier(),
            new GpMeasurementResponseToTcbInfoMapper());
    }

    @Override
    public List<TcbInfoMeasurement> getMeasurementsFromDevice(GpDeviceMeasurementsRequest request) {
        return measurementResponseMapper.map(getMeasurementResponseFromDevice(request));
    }

    private GetMeasurementResponse getMeasurementResponseFromDevice(GpDeviceMeasurementsRequest request) {
        final EcdhKeyPair serviceDhKeyPair = generateEcdhKeyPair();
        final GetMeasurementResponse response = sendGetMeasurement(serviceDhKeyPair, request);

        verifyMeasurementResponse(response, serviceDhKeyPair, request.getAliasPubKey(), request.getDeviceId());

        sendSigmaTeardown(response.getSdmSessionId());

        return response;
    }

    private EcdhKeyPair generateEcdhKeyPair() {
        try {
            return EcdhKeyPair.generate();
        } catch (EcdhKeyPairException e) {
            throw new InternalLibraryException("Failed to generate ECDH keypair.", e);
        }
    }

    private GetMeasurementResponse sendGetMeasurement(EcdhKeyPair serviceDhKeyPair,
                                                      GpDeviceMeasurementsRequest request) {
        return getMeasurementMessageSender
            .withChainType(request.getChainType())
            .send(transportLayer, commandLayer, serviceDhKeyPair, request.getPufType(), request.getContext(),
                request.getCounter());
    }

    private void verifyMeasurementResponse(GetMeasurementResponse response, EcdhKeyPair serviceDhKeyPair,
                                           PublicKey aliasKey, byte[] deviceId) {
        getMeasurementVerifier.verify(aliasKey, response, serviceDhKeyPair);
        deviceIdVerifier.verify(deviceId, response.getDeviceUniqueId());
    }

    private void sendSigmaTeardown(byte[] sdmSessionId) {
        teardownMessageSender.send(transportLayer, commandLayer, sdmSessionId);
    }
}

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

package com.intel.bkp.verifier.service.sender;

import com.intel.bkp.core.endianess.EndianessActor;
import com.intel.bkp.core.manufacturing.model.PufType;
import com.intel.bkp.crypto.ecdh.EcdhKeyPair;
import com.intel.bkp.verifier.command.logger.SigmaLogger;
import com.intel.bkp.verifier.command.messages.attestation.GetMeasurementMessage;
import com.intel.bkp.verifier.command.messages.attestation.GetMeasurementMessageBuilder;
import com.intel.bkp.verifier.command.responses.attestation.GetMeasurementResponse;
import com.intel.bkp.verifier.command.responses.attestation.GetMeasurementResponseBuilder;
import com.intel.bkp.verifier.interfaces.CommandLayer;
import com.intel.bkp.verifier.interfaces.TransportLayer;
import com.intel.bkp.verifier.model.CommandIdentifier;
import com.intel.bkp.verifier.model.RootChainType;
import lombok.NoArgsConstructor;
import lombok.extern.slf4j.Slf4j;

import static com.intel.bkp.verifier.command.logger.SigmaLoggerValues.GET_MEASUREMENT_MESSAGE;

@Slf4j
@NoArgsConstructor
public class GetMeasurementMessageSender {

    private GetMeasurementMessageBuilder getMeasurementMessageBuilder = new GetMeasurementMessageBuilder();
    private BaseMessageSender messageSender = new BaseMessageSender();
    private RootChainType rootChainType = RootChainType.SINGLE;

    public GetMeasurementMessageSender withChainType(RootChainType rootChainType) {
        this.rootChainType = rootChainType;
        return this;
    }

    public GetMeasurementResponse send(TransportLayer transportLayer, CommandLayer commandLayer,
                                       EcdhKeyPair serviceDhKeyPair, PufType pufType, String context, int counter) {
        log.info("Preparing GET_MEASUREMENT ...");
        final GetMeasurementMessage message =
            buildGetMeasurementMessage(serviceDhKeyPair, pufType, context, counter);
        SigmaLogger.log(message, GET_MEASUREMENT_MESSAGE, this.getClass());
        return new GetMeasurementResponseBuilder()
            .withActor(EndianessActor.FIRMWARE)
            .parse(messageSender.send(transportLayer, commandLayer, message,
                CommandIdentifier.GET_MEASUREMENT))
            .withActor(EndianessActor.SERVICE)
            .build();
    }

    private GetMeasurementMessage buildGetMeasurementMessage(EcdhKeyPair serviceDhKeyPair, PufType pufType,
        String context, int counter) {
        return getMeasurementMessageBuilder
            .verifierDhPubKey(serviceDhKeyPair.getPublicKey())
            .pufType(pufType)
            .context(context)
            .counter(counter)
            .userKeyChain(rootChainType)
            .build();
    }
}

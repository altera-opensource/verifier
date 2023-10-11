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

package com.intel.bkp.verifier.protocol.sigma.service;

import com.intel.bkp.command.logger.CommandLogger;
import com.intel.bkp.command.messages.sigma.CreateAttestationSubKeyMessage;
import com.intel.bkp.command.messages.sigma.CreateAttestationSubKeyMessageBuilder;
import com.intel.bkp.command.model.CommandIdentifier;
import com.intel.bkp.command.model.CommandLayer;
import com.intel.bkp.command.responses.sigma.CreateAttestationSubKeyResponseBuilder;
import com.intel.bkp.core.endianness.EndiannessActor;
import com.intel.bkp.core.manufacturing.model.PufType;
import com.intel.bkp.crypto.ecdh.EcdhKeyPair;
import com.intel.bkp.verifier.protocol.common.service.BaseMessageSender;
import com.intel.bkp.verifier.protocol.sigma.model.RootChainType;
import com.intel.bkp.verifier.transport.model.TransportLayer;
import lombok.extern.slf4j.Slf4j;

import static com.intel.bkp.command.logger.CommandLoggerValues.CREATE_ATTESTATION_SUBKEY_MESSAGE;

@Slf4j
public class CreateAttestationSubKeyMessageSender {

    private final CreateAttestationSubKeyMessageBuilder createAttestationSubKeyMessageBuilder =
        new CreateAttestationSubKeyMessageBuilder();
    private final BaseMessageSender messageSender = new BaseMessageSender();
    private final VerifierDHCertBuilder verifierDHCertBuilder = new VerifierDHCertBuilder();
    private final VerifierDhEntryManager verifierDhEntryManager = new VerifierDhEntryManager();

    public CreateAttestationSubKeyResponseBuilder send(
        TransportLayer transportLayer, CommandLayer commandLayer, String context, int counter,
        PufType pufType, EcdhKeyPair serviceDhKeyPair) {
        log.debug("Preparing CREATE_ATTESTATION_SUBKEY ...");
        final CreateAttestationSubKeyMessage subKeyMessage =
            buildCreateSubKeyMessage(context, counter, pufType, serviceDhKeyPair);
        CommandLogger.log(subKeyMessage, CREATE_ATTESTATION_SUBKEY_MESSAGE, this.getClass());
        return new CreateAttestationSubKeyResponseBuilder()
            .withActor(EndiannessActor.FIRMWARE)
            .parse(messageSender.send(transportLayer, commandLayer, subKeyMessage,
                CommandIdentifier.CREATE_ATTESTATION_SUBKEY));
    }

    private CreateAttestationSubKeyMessage buildCreateSubKeyMessage(String context, int counter, PufType pufType,
                                                                    EcdhKeyPair serviceDhKeyPair) {
        byte[] parentKeyChain = verifierDHCertBuilder.getChain(RootChainType.SINGLE);
        return createAttestationSubKeyMessageBuilder
            .verifierDhPubKey(serviceDhKeyPair.getPublicKey())
            .pufType(pufType)
            .context(context)
            .counter(counter)
            .userKeyChain(parentKeyChain, verifierDhEntryManager::getDhEntry)
            .build();
    }
}

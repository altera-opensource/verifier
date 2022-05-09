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
import com.intel.bkp.verifier.command.messages.subkey.CreateAttestationSubKeyMessage;
import com.intel.bkp.verifier.command.messages.subkey.CreateAttestationSubKeyMessageBuilder;
import com.intel.bkp.verifier.command.responses.subkey.CreateAttestationSubKeyResponseBuilder;
import com.intel.bkp.verifier.interfaces.CommandLayer;
import com.intel.bkp.verifier.interfaces.TransportLayer;
import com.intel.bkp.verifier.model.CommandIdentifier;
import lombok.extern.slf4j.Slf4j;

import static com.intel.bkp.verifier.command.logger.SigmaLoggerValues.CREATE_ATTESTATION_SUBKEY_MESSAGE;

@Slf4j
public class CreateAttestationSubKeyMessageSender {

    private CreateAttestationSubKeyMessageBuilder createAttestationSubKeyMessageBuilder =
        new CreateAttestationSubKeyMessageBuilder();
    private BaseMessageSender messageSender = new BaseMessageSender();

    public CreateAttestationSubKeyResponseBuilder send(
        TransportLayer transportLayer, CommandLayer commandLayer, String context, int counter,
        PufType pufType, EcdhKeyPair serviceDhKeyPair) {
        log.info("Preparing CREATE_ATTESTATION_SUBKEY ...");
        final CreateAttestationSubKeyMessage subKeyMessage =
            buildCreateSubKeyMessage(context, counter, pufType, serviceDhKeyPair);
        SigmaLogger.log(subKeyMessage, CREATE_ATTESTATION_SUBKEY_MESSAGE, this.getClass());
        return new CreateAttestationSubKeyResponseBuilder()
            .withActor(EndianessActor.FIRMWARE)
            .parse(messageSender.send(transportLayer, commandLayer, subKeyMessage,
                CommandIdentifier.CREATE_ATTESTATION_SUBKEY));
    }

    private CreateAttestationSubKeyMessage buildCreateSubKeyMessage(String context, int counter, PufType pufType,
        EcdhKeyPair serviceDhKeyPair) {
        return createAttestationSubKeyMessageBuilder
            .verifierDhPubKey(serviceDhKeyPair.getPublicKey())
            .pufType(pufType)
            .context(context)
            .counter(counter)
            .userKeyChain()
            .build();
    }
}

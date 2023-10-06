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
import com.intel.bkp.command.messages.sigma.SigmaTeardownMessage;
import com.intel.bkp.command.messages.sigma.SigmaTeardownMessageBuilder;
import com.intel.bkp.command.model.CommandIdentifier;
import com.intel.bkp.command.model.CommandLayer;
import com.intel.bkp.command.responses.sigma.SigmaTeardownResponseBuilder;
import com.intel.bkp.utils.ByteConverter;
import com.intel.bkp.verifier.protocol.common.service.BaseMessageSender;
import com.intel.bkp.verifier.transport.model.TransportLayer;
import lombok.extern.slf4j.Slf4j;

import static com.intel.bkp.command.logger.CommandLoggerValues.PSGSIGMA_TEARDOWN_MESSAGE;

@Slf4j
public class TeardownMessageSender {

    static final int SESSION_UNKNOWN = -1;

    private SigmaTeardownMessageBuilder sigmaTeardownMessageBuilder = new SigmaTeardownMessageBuilder();
    private BaseMessageSender messageSender = new BaseMessageSender();

    public void send(TransportLayer transportLayer, CommandLayer commandLayer) {
        send(transportLayer, commandLayer, ByteConverter.toBytes(SESSION_UNKNOWN));
    }

    public void send(TransportLayer transportLayer, CommandLayer commandLayer, byte[] sdmSessionId) {
        log.debug("Preparing PSGSIGMA_TEARDOWN ...");
        final SigmaTeardownMessage sigmaTeardown = sigmaTeardownMessageBuilder
            .sdmSessionId(sdmSessionId)
            .build();
        send(transportLayer, commandLayer, sigmaTeardown);
    }

    private void send(TransportLayer transportLayer, CommandLayer commandLayer, SigmaTeardownMessage sigmaTeardown) {
        CommandLogger.log(sigmaTeardown, PSGSIGMA_TEARDOWN_MESSAGE, this.getClass());
        new SigmaTeardownResponseBuilder()
            .parse(messageSender.send(transportLayer, commandLayer, sigmaTeardown, CommandIdentifier.SIGMA_TEARDOWN));
    }
}

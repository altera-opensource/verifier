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

package com.intel.bkp.verifier.protocol.spdm.jna;

import com.intel.bkp.command.exception.JtagUnknownCommandResponseException;
import com.intel.bkp.command.messages.spdm.MctpMessage;
import com.intel.bkp.command.messages.spdm.MctpMessageBuilder;
import com.intel.bkp.command.model.CommandIdentifier;
import com.intel.bkp.command.model.CommandLayer;
import com.intel.bkp.verifier.service.certificate.AppContext;
import com.intel.bkp.verifier.transport.model.TransportLayer;
import lombok.NoArgsConstructor;

import java.nio.ByteBuffer;

@NoArgsConstructor
public class SpdmMessageSender {

    private byte[] response;

    void send(ByteBuffer buffer) throws JtagUnknownCommandResponseException {
        final AppContext appContext = AppContext.instance();
        final CommandLayer commandLayer = appContext.getCommandLayer();
        final TransportLayer transportLayer = appContext.getTransportLayer();

        final MctpMessage mctpMessage = new MctpMessageBuilder().parse(buffer).build();
        final byte[] command = commandLayer.create(mctpMessage, CommandIdentifier.MCTP);

        response = transportLayer.sendCommand(command);
    }

    byte[] receive() {
        final AppContext appContext = AppContext.instance();
        final CommandLayer commandLayer = appContext.getCommandLayer();
        return commandLayer.retrieve(response, CommandIdentifier.MCTP);
    }
}

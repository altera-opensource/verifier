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

package com.intel.bkp.verifier.service.sender;

import com.intel.bkp.verifier.exceptions.TransportLayerException;
import com.intel.bkp.verifier.interfaces.CommandLayer;
import com.intel.bkp.verifier.interfaces.Message;
import com.intel.bkp.verifier.interfaces.TransportLayer;
import com.intel.bkp.verifier.model.CommandIdentifier;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class BaseMessageSenderTest {

    private static final CommandIdentifier COMMAND_IDENTIFIER = CommandIdentifier.SIGMA_TEARDOWN;
    private static final byte[] COMMAND = new byte[4];
    private static final byte[] RESPONSE = new byte[8];
    private static final byte[] RESULT = new byte[12];

    @Mock
    private CommandLayer commandLayer;

    @Mock
    private TransportLayer transportLayer;

    @Mock
    private Message message;

    @InjectMocks
    private BaseMessageSender sut;

    @Test
    void send_Success() {
        // given
        when(commandLayer.create(message, COMMAND_IDENTIFIER)).thenReturn(COMMAND);
        when(transportLayer.sendCommand(COMMAND)).thenReturn(RESPONSE);
        when(commandLayer.retrieve(RESPONSE, COMMAND_IDENTIFIER)).thenReturn(RESULT);

        // when
        final byte[] result =
            sut.send(transportLayer, commandLayer, message, COMMAND_IDENTIFIER);

        // then
        Assertions.assertArrayEquals(RESULT, result);
    }

    @Test
    void send_sendingFail_ThrowsTransportLayerException() {
        // given
        when(commandLayer.create(message, COMMAND_IDENTIFIER)).thenReturn(COMMAND);
        when(transportLayer.sendCommand(COMMAND)).thenThrow(new RuntimeException(""));

        // when-then
        Assertions.assertThrows(TransportLayerException.class,
            () -> sut.send(transportLayer, commandLayer, message, COMMAND_IDENTIFIER));
    }

    @Test
    void send_retrieveFail_ThrowsOriginalException() {
        // given
        when(commandLayer.create(message, COMMAND_IDENTIFIER)).thenReturn(COMMAND);
        when(transportLayer.sendCommand(COMMAND)).thenReturn(RESPONSE);
        when(commandLayer.retrieve(RESPONSE, COMMAND_IDENTIFIER)).thenThrow(new RuntimeException("test"));

        // when-then
        Assertions.assertThrows(RuntimeException.class,
            () -> sut.send(transportLayer, commandLayer, message, COMMAND_IDENTIFIER));
    }
}

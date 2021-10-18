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

import com.intel.bkp.verifier.command.messages.chip.GetChipIdMessage;
import com.intel.bkp.verifier.command.messages.chip.GetChipIdMessageBuilder;
import com.intel.bkp.verifier.command.responses.chip.GetChipIdResponseBuilder;
import com.intel.bkp.verifier.interfaces.CommandLayer;
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
class GetChipIdMessageSenderTest {

    private static final byte[] DEVICE_ID = new byte[] { 1, 1, 2, 2, 3, 3, 4, 4 };
    private static final byte[] RESPONSE = prepareResponse();

    private static byte[] prepareResponse() {
        final GetChipIdResponseBuilder builder = new GetChipIdResponseBuilder();
        builder.setDeviceUniqueId(DEVICE_ID);
        return builder.build().array();
    }

    @Mock
    private CommandLayer commandLayer;

    @Mock
    private TransportLayer transportLayer;

    @Mock
    private GetChipIdMessageBuilder messageBuilder;

    @Mock
    private BaseMessageSender messageSender;

    @Mock
    private GetChipIdMessage message;

    @InjectMocks
    private GetChipIdMessageSender sut;

    @Test
    void send() {
        // given
        when(messageBuilder.build()).thenReturn(message);
        when(messageSender.send(transportLayer, commandLayer, message, CommandIdentifier.GET_CHIPID))
            .thenReturn(RESPONSE);

        // when
        final byte[] result = sut.send(transportLayer, commandLayer);

        // then
        Assertions.assertArrayEquals(DEVICE_ID, result);
    }
}

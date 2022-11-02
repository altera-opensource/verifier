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

package com.intel.bkp.verifier.service.spdm;

import com.intel.bkp.verifier.exceptions.UnknownCommandException;
import com.intel.bkp.verifier.interfaces.CommandLayer;
import com.intel.bkp.verifier.interfaces.TransportLayer;
import com.intel.bkp.verifier.model.CommandIdentifier;
import com.intel.bkp.verifier.service.certificate.AppContext;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.MockedStatic;
import org.mockito.junit.jupiter.MockitoExtension;

import java.nio.ByteBuffer;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mockStatic;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class SpdmMessageSenderTest {

    private static final byte[] COMMAND = new byte[]{1, 2, 3, 4};
    private static final byte[] RESPONSE_NOT_PARSED = new byte[]{5, 6, 7, 8};
    private static final byte[] EXPECTED_RESPONSE = new byte[]{9, 10, 11, 12};

    private static MockedStatic<AppContext> appContextMockedStatic;

    @BeforeAll
    public static void prepareStaticMock() {
        appContextMockedStatic = mockStatic(AppContext.class);
    }

    @AfterAll
    public static void closeStaticMock() {
        appContextMockedStatic.close();
    }


    private final ByteBuffer requestBuffer = ByteBuffer.allocate(100);

    @Mock
    private AppContext appContext;
    @Mock
    private CommandLayer commandLayer;
    @Mock
    private TransportLayer transportLayer;

    @BeforeEach
    void setUp() {
        when(AppContext.instance()).thenReturn(appContext);
        when(appContext.getCommandLayer()).thenReturn(commandLayer);
        when(appContext.getTransportLayer()).thenReturn(transportLayer);
    }

    @Test
    void spdmDeviceSendMessage_Success() {
        // given
        when(commandLayer.create(any(), eq(CommandIdentifier.MCTP))).thenReturn(COMMAND);
        when(transportLayer.sendCommand(eq(COMMAND))).thenReturn(RESPONSE_NOT_PARSED);
        when(commandLayer.retrieve(eq(RESPONSE_NOT_PARSED), eq(CommandIdentifier.MCTP)))
            .thenReturn(EXPECTED_RESPONSE);

        // when
        final byte[] result = SpdmMessageSender.send(requestBuffer);

        // then
        Assertions.assertArrayEquals(EXPECTED_RESPONSE, result);
    }

    @Test
    void spdmDeviceSendMessage_UnknownCommandException_ReturnsSpdmNotSupported() {
        // given
        when(commandLayer.create(any(), eq(CommandIdentifier.MCTP))).thenReturn(COMMAND);
        when(transportLayer.sendCommand(eq(COMMAND))).thenReturn(RESPONSE_NOT_PARSED);
        when(commandLayer.retrieve(eq(RESPONSE_NOT_PARSED), eq(CommandIdentifier.MCTP)))
            .thenThrow(new UnknownCommandException(CommandIdentifier.MCTP.name(), 1, 2, 3));

        // when-then
        Assertions.assertThrows(UnknownCommandException.class, () -> SpdmMessageSender.send(requestBuffer));
    }
}

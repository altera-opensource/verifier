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

package com.intel.bkp.verifier.transport.systemconsole;

import com.intel.bkp.verifier.exceptions.TransportLayerException;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class SystemConsoleTransportImplTest {

    private static final byte[] COMMAND = new byte[]{1, 2, 3, 4};
    private static final String COMMAND_STR = "0x04030201";
    private static final byte[] RESPONSE = new byte[]{1, 0, 2, 0};
    private static final String RESPONSE_STR = "0x00020001";

    @Mock
    private SystemConsoleNioClient client;

    private SystemConsoleTransportImpl sut = new SystemConsoleTransportImpl();

    @BeforeEach
    public void init() {
        sut.setClient(client);
    }

    @Test
    public void initialize_Success() {
        // given
        String connectionConfig = "host:127.0.0.1; port:80; cableID:1";

        // when
        sut.initialize(connectionConfig);

        // then
        verify(client).initialize(any(SystemConsoleConfig.class));
        verify(client).sendPacket(anyString());
    }

    @Test
    public void sendCommand_Success() {
        // given
        String expectedTclCommand = new TclCommands().sendPacket(COMMAND_STR);
        when(client.sendPacket(expectedTclCommand)).thenReturn(RESPONSE_STR);

        // when
        final byte[] result = sut.sendCommand(COMMAND);

        // then
        verify(client).sendPacket(anyString());
        assertArrayEquals(RESPONSE, result);
    }

    @Test
    public void sendCommand_ThrowsException() {
        // given
        doThrow(new TransportLayerException("test")).when(client).sendPacket(anyString());

        // when-then
        assertThrows(TransportLayerException.class, () -> sut.sendCommand(COMMAND));
    }

    @Test
    public void disconnect_Success() {
        // when
        sut.disconnect();

        // then
        verify(client).disconnect();
    }
}

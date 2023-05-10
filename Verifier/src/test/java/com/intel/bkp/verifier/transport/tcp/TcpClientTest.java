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

package com.intel.bkp.verifier.transport.tcp;

import com.intel.bkp.verifier.exceptions.TransportLayerException;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentMatchers;
import org.mockito.Mock;
import org.mockito.Mockito;
import org.mockito.junit.jupiter.MockitoExtension;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.channels.SocketChannel;

import static org.mockito.Mockito.never;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class TcpClientTest {

    private static final byte[] COMMAND = new byte[]{0x00, 0x01, 0x02};

    @Mock
    private SocketChannel socketChannel;

    private TcpClient sut = new TcpClient();

    @Test
    void initialize_Success() {
        // given
        final TcpConfig config = TcpConfig.builder()
            .host("testHost").port(12345).build();

        // when
        Assertions.assertThrows(TransportLayerException.class, () -> sut.initialize(config));
    }

    @Test
    void sendPacket_WithAlmostTooLargeBuffer_Success() throws IOException, TransportLayerException {
        // given
        sut.setSocketChannel(socketChannel);
        int responseLength = TcpClient.RESPONSE_ALLOCATED_SIZE - 1;
        when(socketChannel.read(ArgumentMatchers.any(ByteBuffer.class)))
            .thenReturn(responseLength);

        // when
        byte[] result = sut.sendPacket(COMMAND);

        // then
        Assertions.assertEquals(responseLength, result.length);
    }

    @Test
    void sendPacket_WithTooLargeBuffer_Throws() throws IOException {
        // given
        sut.setSocketChannel(socketChannel);
        when(socketChannel.read(ArgumentMatchers.any(ByteBuffer.class)))
            .thenReturn(TcpClient.RESPONSE_ALLOCATED_SIZE);

        // when-then
        Assertions.assertThrows(TransportLayerException.class,
            () -> sut.sendPacket(new byte[]{0x00, 0x01, 0x02}));
    }

    @Test
    void sendPacket_NotInitialized_Throws() throws IOException {
        // when-then
        Assertions.assertThrows(TransportLayerException.class, () -> sut.sendPacket(COMMAND));

        // then
        Mockito.verify(socketChannel, never()).write(ArgumentMatchers.any(ByteBuffer.class));
        Mockito.verify(socketChannel, never()).read(ArgumentMatchers.any(ByteBuffer.class));
    }

    @Test
    void sendPacket_NoResponseBytesReceived_Throws() throws IOException {
        // given
        sut.setSocketChannel(socketChannel);
        when(socketChannel.read(ArgumentMatchers.any(ByteBuffer.class)))
            .thenReturn(-1);

        // when-then
        Assertions.assertThrows(TransportLayerException.class, () -> sut.sendPacket(COMMAND));
    }

    @Test
    void disconnect_NotInitialized_DoesNothing() {
        // when-then
        Assertions.assertDoesNotThrow(() -> sut.disconnect());
    }
}

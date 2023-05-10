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
import lombok.Setter;
import lombok.SneakyThrows;
import lombok.extern.slf4j.Slf4j;

import java.io.IOException;
import java.net.InetSocketAddress;
import java.nio.ByteBuffer;
import java.nio.channels.SocketChannel;

@Slf4j
public class TcpClient {

    private static final int SLEEP_BEFORE_READ_RESPONSE = 1000; // 1 second
    static final int RESPONSE_ALLOCATED_SIZE = 1024 * 32;

    @Setter
    private SocketChannel socketChannel;

    /**
     * Opens socket connection to Tcp server.
     *
     * @param config connection configuration
     * @throws TransportLayerException exception if any error occurs
     */
    public void initialize(TcpConfig config) {
        try {
            InetSocketAddress socketAddress = new InetSocketAddress(config.getHost(), config.getPort());
            socketChannel = SocketChannel.open(socketAddress);
        } catch (Exception e) {
            throw new TransportLayerException("Failed to open socket", e);
        }
    }

    /**
     * Disconnect and close open socket connection.
     */
    @SneakyThrows
    public void disconnect() {
        if (socketChannel != null) {
            socketChannel.close();
        }
    }

    public byte[] sendPacket(byte[] currentCommand) {
        if (socketChannel == null) {
            throw new TransportLayerException("Connection to not initialized.");
        }

        try {
            socketChannel.write(ByteBuffer.wrap(currentCommand));
            Thread.sleep(SLEEP_BEFORE_READ_RESPONSE);
            ByteBuffer responseBuffer = ByteBuffer.allocate(RESPONSE_ALLOCATED_SIZE);
            final int readBytesCnt = socketChannel.read(responseBuffer);
            log.trace("Read {} bytes from socket.", readBytesCnt);
            if (readBytesCnt <= 0) {
                throw new TransportLayerException("No response bytes received.");
            }
            if (readBytesCnt >= RESPONSE_ALLOCATED_SIZE) {
                throw new TransportLayerException("Response exceeded max allocated size.");
            }

            final byte[] response = new byte[readBytesCnt];
            responseBuffer.rewind();
            responseBuffer.get(response);

            return response;
        } catch (IOException e) {
            throw new TransportLayerException("Failed to send packet", e);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new TransportLayerException("Failed to send packet", e);
        }
    }
}

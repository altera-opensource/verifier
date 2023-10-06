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

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.channels.SocketChannel;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class SystemConsoleNioClientTest {

    private static final String COMMAND = "0x10000012";
    private static final String UNPROCESSED_RESPONSE = "return \"/channels/remote58/(lib)/packet_1\"\n"
        + "\n"
        + "tcl>\n"
        + "puts stdout \"COMMAND = 0x10000012\"\n"
        + "return \"\"\n"
        + "\n"
        + "tcl>\n"
        + "return \"0x10002000 0x13f5567d 0x80d02eb6\"\n"
        + "\n"
        + "tcl>\n"
        + "puts stdout \"COMMAND_RESULT = 0x10002000 0x13f5567d 0x80d02eb6\"\n"
        + "return \"\"";
    private static final String RESPONSE = "0x10002000 0x13f5567d 0x80d02eb6";


    @Mock
    private SocketChannel socketChannel;

    private SystemConsoleNioClient sut = new SystemConsoleNioClient();

    @Test
    void sendPacket_responseProcessing_Success() throws IOException {
        // given
        String tclCommand = new TclCommands().sendPacket(COMMAND);
        sut.setSocketChannel(socketChannel);
        when(socketChannel.read(any(ByteBuffer.class)))
            .thenAnswer(invocation -> {
                ByteBuffer buffer = invocation.getArgument(0);
                final byte[] bytes = UNPROCESSED_RESPONSE.getBytes();
                buffer.put(bytes);
                return bytes.length;
            });

        // when-then
        assertEquals(RESPONSE, sut.sendPacket(tclCommand));
    }
}

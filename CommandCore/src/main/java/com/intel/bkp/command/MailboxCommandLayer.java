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

package com.intel.bkp.command;

import com.intel.bkp.command.header.CommandHeader;
import com.intel.bkp.command.header.CommandHeaderManager;
import com.intel.bkp.command.model.CommandIdentifier;
import com.intel.bkp.command.model.CommandLayer;
import com.intel.bkp.command.model.Message;
import com.intel.bkp.utils.ByteBufferSafe;
import lombok.extern.slf4j.Slf4j;

import java.nio.ByteBuffer;

import static com.intel.bkp.utils.HexConverter.toHex;

@Slf4j
public class MailboxCommandLayer implements CommandLayer {

    private static final int COMMAND_HEADER_LEN = 4;
    private static final int CLIENT_IDENTIFIER = 1;

    @Override
    public byte[] create(Message data, CommandIdentifier command) {
        final int commandCode = command.getCommandCode();
        final byte[] dataBytes = data.array();
        final byte[] header = buildCommandHeader(commandCode, getArgumentsLen(dataBytes), 0, CLIENT_IDENTIFIER);
        final byte[] rawData = withAppendedHeader(dataBytes, header);
        log.trace("Sending raw data for command {}: {}", command.name(), toHex(rawData));
        return rawData;
    }

    @Override
    public byte[] retrieve(byte[] data, CommandIdentifier command) {
        log.trace("Received raw data for response {}: {}", command.name(), toHex(data));
        CommandHeaderManager.validateCommandHeaderCode(data, command.name());
        return ByteBufferSafe.wrap(data).skip(COMMAND_HEADER_LEN).getRemaining();
    }

    protected int getArgumentsLen(byte[] dataBytes) {
        return (int) Math.ceil((double) dataBytes.length / Integer.BYTES);
    }

    protected byte[] buildCommandHeader(int commandCode, int argumentsLength, int id, int client) {
        return CommandHeaderManager.buildForFw(new CommandHeader(commandCode, argumentsLength, id, client));
    }

    protected byte[] withAppendedHeader(byte[] data, byte[] header) {
        return ByteBuffer.allocate(header.length + data.length)
            .put(header)
            .put(data)
            .array();
    }
}

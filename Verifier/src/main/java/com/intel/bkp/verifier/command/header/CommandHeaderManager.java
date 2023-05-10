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

package com.intel.bkp.verifier.command.header;

import com.intel.bkp.utils.ByteBufferSafe;
import com.intel.bkp.utils.ByteConverter;
import com.intel.bkp.utils.ByteSwap;
import com.intel.bkp.verifier.exceptions.CommandFailedException;
import com.intel.bkp.verifier.exceptions.CommandHeaderValidationException;
import com.intel.bkp.verifier.exceptions.JtagResponseException;
import com.intel.bkp.verifier.exceptions.UnknownCommandException;
import lombok.AccessLevel;
import lombok.NoArgsConstructor;
import lombok.extern.slf4j.Slf4j;

import java.util.Collections;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

import static com.intel.bkp.utils.ByteSwapOrder.B2L;
import static com.intel.bkp.utils.ByteSwapOrder.L2B;

@Slf4j
@NoArgsConstructor(access = AccessLevel.PRIVATE)
public class CommandHeaderManager {

    private static final int COMMAND_HEADER_LEN = Integer.BYTES;
    private static final int COMMAND_HEADER_LEN_BITS = COMMAND_HEADER_LEN * Byte.SIZE;
    private static final String COMMAND_HEADER_NOT_SET = "Command header is not set.";
    private static final String COMMAND_HEADER_INVALID_LENGTH = "Command header length is '%d', but should be '%d'.";

    public static byte[] buildForFw(CommandHeader commandHeader) {
        return ByteSwap.getSwappedArrayByInt(CommandHeaderManager.build(commandHeader), B2L);
    }

    public static byte[] build(CommandHeader commandHeader) {
        int headerFinalValue = 0;
        for (HeaderFields headerField : HeaderFields.values()) {
            headerFinalValue |= commandHeader.getFields().get(headerField) << headerField.getOffset();
        }
        return ByteConverter.toBytes(headerFinalValue);
    }

    public static CommandHeader parseFromFw(byte[] commandHeader) throws CommandHeaderValidationException {
        return CommandHeaderManager.parse(ByteSwap.getSwappedArrayByInt(commandHeader, L2B));
    }

    public static CommandHeader parse(byte[] commandHeader) throws CommandHeaderValidationException {
        if (commandHeader == null) {
            throw new CommandHeaderValidationException(COMMAND_HEADER_NOT_SET);
        }

        verifyCommandHeaderLength(commandHeader.length);

        final int headerFinalValue = ByteBufferSafe.wrap(commandHeader).getInt();
        Map<HeaderFields, Integer> map = new ConcurrentHashMap<>();
        for (HeaderFields headerField : HeaderFields.values()) {
            // to take int value of header -> cut all bits to the left and then to the right
            final int shiftLeft = COMMAND_HEADER_LEN_BITS
                - headerField.getOffset() - headerField.getSize();
            final int shiftRight = COMMAND_HEADER_LEN_BITS - headerField.getSize();

            int headerValue = headerFinalValue << shiftLeft;
            headerValue = headerValue >>> shiftRight;
            map.put(headerField, headerValue);
        }
        return new CommandHeader(Collections.unmodifiableMap(map));
    }

    public static void validateCommandHeaderCode(byte[] command, String commandName) {
        try {
            if (command.length < COMMAND_HEADER_LEN) {
                throw new CommandHeaderValidationException("No command header in response.");
            }

            byte[] header = new byte[COMMAND_HEADER_LEN];
            ByteBufferSafe.wrap(command).get(header);

            final CommandHeader parsedHeader = CommandHeaderManager.parseFromFw(header);
            throwOnError(commandName, parsedHeader);
        } catch (CommandHeaderValidationException e) {
            throw new JtagResponseException(
                String.format("Failed to parse command [%s] header from response.", commandName));
        }
    }

    private static void verifyCommandHeaderLength(int length) throws CommandHeaderValidationException {
        if (length != COMMAND_HEADER_LEN) {
            throw new CommandHeaderValidationException(
                String.format(COMMAND_HEADER_INVALID_LENGTH, length, COMMAND_HEADER_LEN));
        }
    }

    private static void throwOnError(String responseName, CommandHeader parsedHeader) {
        if (FwErrorCodes.UNKNOWN_COMMAND.getCode() == parsedHeader.getCode()) {
            throw new UnknownCommandException(responseName, parsedHeader);
        }

        if (FwErrorCodes.STATUS_OKAY.getCode() != parsedHeader.getCode()) {
            throw new CommandFailedException(responseName, parsedHeader);
        }
    }
}

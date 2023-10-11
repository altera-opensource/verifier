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
import com.intel.bkp.verifier.transport.tcp.TcpClient;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.lang3.StringUtils;

import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.stream.Collectors;

@Slf4j
public class SystemConsoleNioClient extends TcpClient {

    /**
     * Sends packet using socket with or without response.
     */
    public String sendPacket(String currentCommand) {
        final byte[] responseBytes = sendPacket(currentCommand.getBytes(StandardCharsets.UTF_8));
        final String fullResponse = new String(responseBytes);
        log.trace("Full response: {}", fullResponse);
        final String processedResponse = processResponse(fullResponse);
        if (processedResponse.contains("error")) {
            throw new TransportLayerException(String.format("SystemConsole responded with error: %s",
                processedResponse));
        }

        return processedResponse;
    }

    private String processResponse(String response) {
        final String replacePattern = "puts stdout|\"|tcl>|return\\s(.*)|COMMAND\\s=\\s(.*)|COMMAND_RESULT\\s=\\s";
        return Arrays.stream(response.split(System.lineSeparator()))
            .map(s -> s.replaceAll(replacePattern, "").trim())
            .filter(StringUtils::isNotBlank)
            .collect(Collectors.joining());
    }
}

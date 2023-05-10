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

import com.intel.bkp.verifier.exceptions.TclCommandException;
import org.apache.commons.io.IOUtils;

import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.util.Optional;

public class TclCommands {

    private static final String SYSTEM_CONSOLE_RESOURCE_PATH = "system-console/";
    private static final String EMPTY_CABLE_ID = "\"\"";

    static final String CABLE_ID = "!!CABLE_ID!!";
    static final String COMMAND = "!!COMMAND!!";

    public String initialize(Integer cableId) {
        final String scriptRaw = loadScriptFile("initialize-script.txt");
        return scriptRaw.replaceAll(CABLE_ID,
            Optional.ofNullable(cableId)
                .map(String::valueOf)
                .orElse(EMPTY_CABLE_ID)
        );
    }

    public String sendPacket(String command) {
        final String scriptRaw = loadScriptFile("send-packet-script.txt");
        return scriptRaw.replaceAll(COMMAND, EscapeUtils.escape(command));
    }

    private String loadScriptFile(String scriptFile) {
        ClassLoader classLoader = getClass().getClassLoader();
        try (InputStream inputStream = classLoader.getResourceAsStream(SYSTEM_CONSOLE_RESOURCE_PATH + scriptFile)) {
            assert inputStream != null;
            return IOUtils.toString(inputStream, StandardCharsets.UTF_8);
        } catch (IOException e) {
            throw new TclCommandException("Failed to load resource file: " + scriptFile, e);
        }
    }
}

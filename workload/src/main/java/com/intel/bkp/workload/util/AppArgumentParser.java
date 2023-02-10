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

package com.intel.bkp.workload.util;

import lombok.AccessLevel;
import lombok.NoArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.cli.CommandLine;
import org.apache.commons.cli.CommandLineParser;
import org.apache.commons.cli.DefaultParser;
import org.apache.commons.cli.HelpFormatter;
import org.apache.commons.cli.Option;
import org.apache.commons.cli.Options;
import org.apache.commons.cli.ParseException;

@Slf4j
@NoArgsConstructor(access = AccessLevel.PRIVATE)
public class AppArgumentParser {

    private static final String WORKLOAD_APP_DESC =
        "WorkloadApp --command GET --transport-id \"host:127.0.0.1;port:50001\" "
            + "--ref-measurement /path/to/reference.rim --slot-id 0x02";

    public static AppArgument parseArguments(String[] args) {
        Options options = getOptions();

        CommandLineParser parser = new DefaultParser();
        HelpFormatter formatter = new HelpFormatter();
        CommandLine cmd = null;

        try {
            cmd = parser.parse(options, args);
        } catch (ParseException e) {
            log.error("[WORKLOAD] Failed to parse arguments: {}", e.getMessage());
            log.debug("Stacktrace: ", e);
            formatter.printHelp(WORKLOAD_APP_DESC, options);
            System.exit(1);
        }

        return AppArgument.instance()
            .transportId(cmd.getOptionValue("transport-id").trim())
            .context(cmd.getOptionValue("context"))
            .pufType(cmd.getOptionValue("puf-type"))
            .refMeasurement(cmd.getOptionValue("ref-measurement"))
            .command(cmd.getOptionValue("command").trim())
            .logLevel(cmd.getOptionValue("log-level"))
            .build();
    }

    private static Options getOptions() {
        Options options = new Options();

        Option transportId = new Option("i", "transport-id", true, "JTAG Identifier");
        transportId.setRequired(true);
        options.addOption(transportId);

        Option command = new Option("c", "command", true, "Command which should be invoked. "
            + "Possible values: CREATE, GET, HEALTH");
        command.setRequired(true);
        options.addOption(command);

        Option context = new Option(null, "context", true, "Random value provided as seed");
        options.addOption(context);

        Option pufType = new Option(null, "puf-type", true, "Puf type enum value. "
            + "Possible values: IID, INTEL, EFUSE, IIDUSER, INTEL_USER");
        options.addOption(pufType);

        Option refMeasure = new Option(null, "ref-measurement", true, "Path to Reference Integrity Manifest (RIM)");
        options.addOption(refMeasure);

        Option logLevel = new Option(null, "log-level", true, "Logging level. "
            + "Possible values: OFF, ERROR, WARN, INFO (default), DEBUG, TRACE");
        options.addOption(logLevel);

        return options;
    }
}

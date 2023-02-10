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

package com.intel.bkp.fpgacerts.dice.tcbinfo;

import com.intel.bkp.fpgacerts.dice.tcbinfo.parsing.FwidFieldParser;
import com.intel.bkp.fpgacerts.dice.tcbinfo.parsing.ITcbInfoFieldParser;
import com.intel.bkp.fpgacerts.dice.tcbinfo.parsing.IntegerFieldParser;
import com.intel.bkp.fpgacerts.dice.tcbinfo.parsing.OctetStringFieldParser;
import com.intel.bkp.fpgacerts.dice.tcbinfo.parsing.OidFieldParser;
import com.intel.bkp.fpgacerts.dice.tcbinfo.parsing.OperationalFlagsFieldParser;
import com.intel.bkp.fpgacerts.dice.tcbinfo.parsing.StringFieldParser;
import com.intel.bkp.fpgacerts.exceptions.TcbInfoFieldException;
import lombok.AllArgsConstructor;
import lombok.Getter;

import java.util.Arrays;

/**
 * Order of fields matters.
 */
@Getter
@AllArgsConstructor
public enum TcbInfoField {
    VENDOR(new StringFieldParser()), // key
    MODEL(new StringFieldParser()), // key
    VERSION(new StringFieldParser()), // value
    SVN(new IntegerFieldParser()), // value
    LAYER(new IntegerFieldParser()), // key
    INDEX(new IntegerFieldParser()), // key
    FWIDS(new FwidFieldParser()), // value
    FLAGS(new OperationalFlagsFieldParser()), // value
    VENDOR_INFO(new OctetStringFieldParser()), // value
    TYPE(new OidFieldParser()); // key

    private final ITcbInfoFieldParser parser;

    static final String UNSUPPORTED_FIELD = "Unsupported TcbInfoField: %d.";

    public static TcbInfoField from(int tagNo) {
        return Arrays.stream(values())
            .filter(type -> type.ordinal() == tagNo)
            .findFirst()
            .orElseThrow(
                () -> new TcbInfoFieldException(String.format(UNSUPPORTED_FIELD, tagNo))
            );
    }
}

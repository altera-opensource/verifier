/*
 * This project is licensed as below.
 *
 * **************************************************************************
 *
 * Copyright 2020-2021 Intel Corporation. All Rights Reserved.
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

package com.intel.bkp.verifier.service.measurements.validator;

import com.intel.bkp.ext.utils.ByteBufferSafe;
import org.apache.commons.lang3.StringUtils;

import java.nio.ByteBuffer;

import static com.intel.bkp.ext.utils.HexConverter.fromHex;
import static com.intel.bkp.ext.utils.HexConverter.toHex;

public class DeviceStateMaskHelper {

    public static final int INTEGER_HEX_LEN = 8;

    public static String getMask(String value, String mask) {
        if (StringUtils.isBlank(mask)) {
            mask = StringUtils.repeat("F", value.length());
        }
        return padStringToMakeInteger(mask);
    }

    public static String applyMask(String value, String mask) {
        value = alignValueToMask(value, mask);

        final byte[] valueBytes = fromHex(value);
        final byte[] maskBytes = fromHex(mask);
        return toHex(applyMask(valueBytes, maskBytes));
    }

    private static byte[] applyMask(byte[] value, byte[] mask) {
        ByteBufferSafe maskBuffer = ByteBufferSafe.wrap(mask);
        ByteBufferSafe valueBuffer = ByteBufferSafe.wrap(value);

        ByteBuffer maskedOutput = ByteBuffer.allocate(value.length);
        while (valueBuffer.remaining() > 0) {
            int valueInt = valueBuffer.getInt();
            int maskInt = maskBuffer.getInt();
            int maskedInt = valueInt & maskInt;
            maskedOutput.putInt(maskedInt);
        }
        return maskedOutput.array();
    }

    private static String padStringToMakeInteger(String str) {
        final int strLen = str.length();
        if (strLen % INTEGER_HEX_LEN != 0) { // to make 4-byte integer for applying mask
            return StringUtils.leftPad(str, strLen + INTEGER_HEX_LEN - (strLen % INTEGER_HEX_LEN), "0");
        }
        return str;
    }

    private static String alignValueToMask(String value, String mask) {
        if (value.length() <= mask.length()) {
            return StringUtils.leftPad(value, mask.length(), "0");
        } else {
            return StringUtils.truncate(value, value.length() - mask.length(), mask.length());
        }
    }
}

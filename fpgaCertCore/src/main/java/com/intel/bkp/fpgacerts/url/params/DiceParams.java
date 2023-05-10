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

package com.intel.bkp.fpgacerts.url.params;

import com.intel.bkp.fpgacerts.utils.DeviceIdUtil;
import lombok.AllArgsConstructor;
import lombok.Getter;

import java.util.Locale;

/**
 * ski - Subject Key Identifier
 * uid - same as deviceId/chipId but reversed by 8-bytes, eg. deviceId = 0102030405060708 -> uid = 0807060504030201.
 * This is because FM/DM certificates on Distribution Point have different naming convention than S10.
 */
@AllArgsConstructor
public class DiceParams {

    @Getter
    private final String ski;

    private final String uid;

    public String getUid() {
        return uid.toLowerCase(Locale.ROOT);
    }

    @Override
    public String toString() {
        return String.format("DiceParams(SKI = %s, UID = %s (in Distribution Point format: %s))",
                getSki(), getUidInLogsFormat(), getUid());
    }

    protected final String getUidInLogsFormat() {
        // uid is used in diceParams on purpose (it is in Distribution Point format)
        // reversed uid (in little endian) is used to present it in logs in consistent format (as received from
        // GET_CHIPID)
        return DeviceIdUtil.getReversed(uid);
    }
}

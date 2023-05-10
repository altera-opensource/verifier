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

package com.intel.bkp.utils;

import lombok.AccessLevel;
import lombok.NoArgsConstructor;

import java.util.Date;

@NoArgsConstructor(access = AccessLevel.PRIVATE)
public class X509DateBuilderHelper {

    public static Date notBefore() {
        return DateBuilder.now().build();
    }

    public static String notBeforeDate() {
        return DateBuilder.now().build(DateBuilder.DATE);
    }

    public static Date notAfter(Integer validityYears) {
        return DateBuilder.now().addYear(validityYears).build();
    }

    public static Date notAfter(Date fromDate, Integer validityHours) {
        return DateBuilder.from(fromDate).addHour(validityHours).build();
    }

    public static Date notAfter() {
        return DateBuilder.infinite().build();
    }

    public static String notAfterDate() {
        return DateBuilder.infinite().build(DateBuilder.DATE);
    }

    public static String notAfterDate(Integer validityYears) {
        return DateBuilder.now().addYear(validityYears).build(DateBuilder.DATE);
    }

    public static String notAfterDateTime(Integer validityHours) {
        return DateBuilder.now().addHour(validityHours).build(DateBuilder.DATE_TIME);
    }
}

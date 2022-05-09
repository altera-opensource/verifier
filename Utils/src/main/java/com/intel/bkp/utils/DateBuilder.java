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

package com.intel.bkp.utils;

import lombok.AllArgsConstructor;

import java.time.Instant;
import java.time.ZoneId;
import java.time.format.DateTimeFormatter;
import java.util.Calendar;
import java.util.Date;

@AllArgsConstructor
public class DateBuilder {

    public static final ZoneId UTC_ZONE = ZoneId.of("UTC");

    public static final DateTimeFormatter DATE
        = DateTimeFormatter.ofPattern("yyyy-MM-dd").withZone(UTC_ZONE);
    public static final DateTimeFormatter DATE_TIME
        = DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss").withZone(UTC_ZONE);

    private Date value;

    public static DateBuilder now() {
        return new DateBuilder(Date.from(Instant.now()));
    }

    public static DateBuilder from(Date date) {
        return new DateBuilder(date);
    }

    public static DateBuilder infinite() {
        var endOfTime = Instant.now()
            .atZone(UTC_ZONE)
            .withYear(9999)
            .withMonth(12)
            .withDayOfMonth(31)
            .withHour(23)
            .withMinute(59)
            .withSecond(59)
            .toInstant();
        return new DateBuilder(Date.from(endOfTime));
    }

    public DateBuilder addHour(Integer value) {
        this.value = getDatePlus(Calendar.HOUR, value);
        return this;
    }

    public DateBuilder addYear(Integer value) {
        this.value = getDatePlus(Calendar.YEAR, value);
        return this;
    }

    public Date build() {
        return this.value;
    }

    public String build(DateTimeFormatter format) {
        return format.format(value.toInstant());
    }

    private Date getDatePlus(int timeUnit, int value) {
        final Calendar calendar = Calendar.getInstance();
        calendar.setTime(this.value);
        calendar.add(timeUnit, value);
        return calendar.getTime();
    }
}

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

import lombok.Getter;

import java.util.List;

@Getter
public class TcbInfoMeasurement {

    private final TcbInfoKey key;
    private final TcbInfoValue value;

    public TcbInfoMeasurement(TcbInfo tcbInfo) {
        key = TcbInfoKey.from(tcbInfo);
        value = TcbInfoValue.from(tcbInfo);
    }

    public static TcbInfoMeasurement empty() {
        return new TcbInfoMeasurement(new TcbInfo());
    }

    public static List<TcbInfoMeasurement> asMeasurements(List<TcbInfo> tcbInfos) {
        return tcbInfos.stream().map(TcbInfoMeasurement::new).toList();
    }

    public static boolean containsAllReferenceMeasurements(List<TcbInfoMeasurement> measurements,
                                                           List<TcbInfoMeasurement> referenceMeasurements) {
        return referenceMeasurements.stream()
            .allMatch(referenceMeasurement -> containsReferenceMeasurement(measurements, referenceMeasurement));

    }

    private static boolean containsReferenceMeasurement(List<TcbInfoMeasurement> measurements,
                                                        TcbInfoMeasurement referenceMeasurement) {
        return measurements.stream()
            .anyMatch(measurement -> measurement.matchesReferenceMeasurement(referenceMeasurement));
    }

    public boolean matchesReferenceMeasurement(TcbInfoMeasurement referenceMeasurement) {
        return hasTheSameName(referenceMeasurement)
            && value.matchesReferenceValue(referenceMeasurement.getValue());
    }

    private boolean hasTheSameName(TcbInfoMeasurement measurement) {
        return key.equals(measurement.getKey());
    }

    @Override
    public boolean equals(Object o) {
        if (o == null) {
            return false;
        } else if (o == this) {
            return true;
        } else if (o instanceof TcbInfoMeasurement tcbInfoMeasurement) {
            return hasTheSameName(tcbInfoMeasurement)
                && value.equals(tcbInfoMeasurement.getValue());
        } else {
            return false;
        }
    }

    @Override
    public String toString() {
        return "TcbInfoMeasurement(\n%s\n%s\n)".formatted(key.toString(), value.toString());
    }
}

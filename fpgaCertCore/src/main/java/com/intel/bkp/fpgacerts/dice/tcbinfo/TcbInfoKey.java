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

package com.intel.bkp.fpgacerts.dice.tcbinfo;

import lombok.AccessLevel;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.util.Optional;

import static com.intel.bkp.fpgacerts.utils.ToStringUtils.includeIfNonNull;

@Data
@Builder
@AllArgsConstructor(access = AccessLevel.PACKAGE)
@NoArgsConstructor
public class TcbInfoKey {

    private static final TcbInfoKey EMPTY = new TcbInfoKey();

    private String vendor;
    private String model;
    private Integer layer;
    private Integer index;
    private String type;

    private TcbInfoKey(Integer layer) {
        this.layer = layer;
        this.vendor = TcbInfoConstants.VENDOR;
    }

    public static TcbInfoKey from(MeasurementType measurementType) {
        final TcbInfoKey key = new TcbInfoKey(measurementType.getLayer());
        key.setType(measurementType.getOid());
        return key;
    }

    public static TcbInfoKey from(MeasurementType measurementType, String model) {
        final TcbInfoKey key = new TcbInfoKey(measurementType.getLayer());
        key.setModel(model);
        key.setIndex(TcbInfoConstants.INDEX);
        return key;
    }

    public static TcbInfoKey from(TcbInfo tcbInfo) {
        final TcbInfoKey key = new TcbInfoKey();

        final Optional<String> vendorField = tcbInfo.get(TcbInfoField.VENDOR);
        vendorField.ifPresent(key::setVendor);

        final Optional<String> modelField = tcbInfo.get(TcbInfoField.MODEL);
        modelField.ifPresent(key::setModel);

        final Optional<Integer> layerField = tcbInfo.get(TcbInfoField.LAYER);
        layerField.ifPresent(key::setLayer);

        final Optional<Integer> indexField = tcbInfo.get(TcbInfoField.INDEX);
        indexField.ifPresent(key::setIndex);

        final Optional<String> typeField = tcbInfo.get(TcbInfoField.TYPE);
        typeField.ifPresent(key::setType);

        return key;
    }

    public boolean isEmpty() {
        return this.equals(EMPTY);
    }

    @Override
    public String toString() {
        return "TcbInfoKey("
            + includeIfNonNull("vendor", vendor)
            + includeIfNonNull("model", model)
            + includeIfNonNull("layer", layer)
            + includeIfNonNull("index", index)
            + includeIfNonNull("type", type)
            + " )";
    }
}

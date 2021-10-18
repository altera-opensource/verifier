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

package com.intel.bkp.verifier.model.dice;

import lombok.Data;

import java.util.Map;

import static com.intel.bkp.verifier.model.dice.Constants.INDEX_DEFAULT_VALUE;
import static com.intel.bkp.verifier.model.dice.ToStringUtils.includeIfNonNull;

@Data
public class TcbInfoKey {

    private String vendor;
    private String model;
    private Integer layer;
    private Integer index;
    private String type;

    public static TcbInfoKey from(TcbInfo tcbInfo) {
        final TcbInfoKey key = new TcbInfoKey();
        final Map<TcbInfoField, Object> map = tcbInfo.getTcbInfo();

        if (map.containsKey(TcbInfoField.VENDOR)) {
            key.setVendor((String)map.get(TcbInfoField.VENDOR));
        }

        if (map.containsKey(TcbInfoField.MODEL)) {
            key.setModel((String)map.get(TcbInfoField.MODEL));
        }

        if (map.containsKey(TcbInfoField.LAYER)) {
            key.setLayer((Integer)map.get(TcbInfoField.LAYER));
        }

        if (map.containsKey(TcbInfoField.INDEX)) {
            key.setIndex((Integer)map.get(TcbInfoField.INDEX));
        } else {
            key.setIndex(INDEX_DEFAULT_VALUE);
        }

        if (map.containsKey(TcbInfoField.TYPE)) {
            key.setType((String)map.get(TcbInfoField.TYPE));
        }

        return key;
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

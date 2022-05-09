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

package com.intel.bkp.verifier.model.evidence;

import com.intel.bkp.fpgacerts.dice.tcbinfo.FwIdField;
import com.intel.bkp.fpgacerts.dice.tcbinfo.TcbInfo;
import com.intel.bkp.fpgacerts.dice.tcbinfo.TcbInfoConstants;
import com.intel.bkp.fpgacerts.dice.tcbinfo.TcbInfoField;
import com.intel.bkp.fpgacerts.dice.tcbinfo.vendorinfo.MaskedVendorInfo;

import java.util.EnumMap;
import java.util.Locale;
import java.util.Map;

import static java.util.Objects.isNull;
import static org.apache.commons.lang3.StringUtils.isNotBlank;

public class BaseEvidenceBlockToTcbInfoMapper {

    public TcbInfo map(BaseEvidenceBlock block) {
        final Map<TcbInfoField, Object> tcbInfoMap = new EnumMap<>(TcbInfoField.class);

        if (isNotBlank(block.getVendor())) {
            tcbInfoMap.put(TcbInfoField.VENDOR, block.getVendor());
        }

        if (isNotBlank(block.getModel())) {
            tcbInfoMap.put(TcbInfoField.MODEL, block.getModel());
        }

        if (isNotBlank(block.getLayer())) {
            tcbInfoMap.put(TcbInfoField.LAYER, Integer.parseInt(block.getLayer()));
        }

        if (!isNull(block.getIndex())) {
            tcbInfoMap.put(TcbInfoField.INDEX, block.getIndex());
        } else {
            tcbInfoMap.put(TcbInfoField.INDEX, TcbInfoConstants.INDEX);
        }

        // Assumption is that there is only 1 element in list for SHA384.
        // The assumption may change in future.
        if (!isNull(block.getFwids()) && !block.getFwids().isEmpty()) {
            final FwIdField field = block.getFwids().get(0);
            field.setHashAlg(field.getHashAlg().toUpperCase(Locale.ROOT));
            field.setDigest(field.getDigest().toUpperCase(Locale.ROOT));
            tcbInfoMap.put(TcbInfoField.FWIDS, field);
        }

        if (isNotBlank(block.getVendorInfo()) && isNotBlank(block.getVendorInfoMask())) {
            tcbInfoMap.put(TcbInfoField.VENDOR_INFO,
                new MaskedVendorInfo(
                    block.getVendorInfo().toUpperCase(Locale.ROOT),
                    block.getVendorInfoMask().toUpperCase(Locale.ROOT)
                )
            );
        }

        if (isNotBlank(block.getType())) {
            tcbInfoMap.put(TcbInfoField.TYPE, block.getType().toUpperCase(Locale.ROOT));
        }

        return new TcbInfo(tcbInfoMap);
    }
}

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

import com.intel.bkp.fpgacerts.dice.tcbinfo.vendorinfo.MaskedVendorInfo;
import com.intel.bkp.fpgacerts.dice.tcbinfo.vendorinfo.MaskedVendorInfoFactory;
import lombok.EqualsAndHashCode;
import lombok.Getter;
import lombok.RequiredArgsConstructor;
import lombok.Setter;

import java.util.Optional;
import java.util.function.BiFunction;
import java.util.function.Function;

import static com.intel.bkp.fpgacerts.dice.tcbinfo.TcbInfoField.FLAGS;
import static com.intel.bkp.fpgacerts.dice.tcbinfo.TcbInfoField.FWIDS;
import static com.intel.bkp.fpgacerts.dice.tcbinfo.TcbInfoField.SVN;
import static com.intel.bkp.fpgacerts.dice.tcbinfo.TcbInfoField.VENDOR_INFO;
import static com.intel.bkp.fpgacerts.dice.tcbinfo.TcbInfoField.VERSION;
import static com.intel.bkp.fpgacerts.utils.ToStringUtils.includeIfPresent;

@Getter
@Setter
@RequiredArgsConstructor
@EqualsAndHashCode
public class TcbInfoValue {

    private static final TcbInfoValue EMPTY = new TcbInfoValue();

    private Optional<String> version = Optional.empty();
    private Optional<Integer> svn = Optional.empty();
    private Optional<FwIdField> fwid = Optional.empty();
    private Optional<MaskedVendorInfo> maskedVendorInfo = Optional.empty();
    private Optional<String> flags = Optional.empty();

    public static TcbInfoValue from(TcbInfo tcbInfo) {
        final TcbInfoValue value = new TcbInfoValue();

        value.setVersion(tcbInfo.get(VERSION));
        value.setSvn(tcbInfo.get(SVN));
        value.setFwid(tcbInfo.get(FWIDS));
        value.setMaskedVendorInfo(tcbInfo.get(VENDOR_INFO).map(MaskedVendorInfoFactory::get));
        value.setFlags(tcbInfo.get(FLAGS));

        return value;
    }

    public boolean isEmpty() {
        return this.equals(EMPTY);
    }

    @Override
    public String toString() {
        return "TcbInfoValue("
            + includeIfPresent("version", version)
            + includeIfPresent("svn", svn)
            + includeIfPresent("fwid", fwid)
            + includeIfPresent("maskedVendorInfo", maskedVendorInfo)
            + includeIfPresent("flags", flags)
            + " )";
    }

    //note for pentesting: this could potentially be a logic tweak
    public boolean matchesReferenceValue(TcbInfoValue referenceValue) {
        return matchesReferenceValue(referenceValue, TcbInfoValue::getVersion, String::equals)
            && matchesReferenceValue(referenceValue, TcbInfoValue::getSvn, Integer::equals)
            && matchesReferenceValue(referenceValue, TcbInfoValue::getFwid, FwIdField::equals)
            && matchesReferenceValue(referenceValue, TcbInfoValue::getMaskedVendorInfo, MaskedVendorInfo::equals)
            && matchesReferenceValue(referenceValue, TcbInfoValue::getFlags, String::equals);
    }

    private <T> boolean matchesReferenceValue(TcbInfoValue referenceValue,
                                              Function<TcbInfoValue, Optional<T>> getField,
                                              BiFunction<T, T, Boolean> match) {
        return getField.apply(referenceValue)
            .map(referenceFieldValue -> getField.apply(this)
                .map(actualFieldValue -> match.apply(actualFieldValue, referenceFieldValue))
                .orElse(false))
            .orElse(true);
    }
}

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

package com.intel.bkp.fpgacerts.dice.tcbinfo.vendorinfo;

import com.intel.bkp.utils.MaskHelper;
import lombok.AllArgsConstructor;

import java.util.Objects;

import static java.util.Objects.nonNull;

@AllArgsConstructor
public class MaskedVendorInfoComparator {

    private MaskedVendorInfo left;
    private MaskedVendorInfo right;

    public boolean areEqual() {
        if (isBothVendorInfoSet() && isOneMaskSetWhenOtherIsNull()) {
            return equalsFromResponse();
        }

        return equalsInternal();
    }

    private boolean isBothVendorInfoSet() {
        return nonNull(left.getVendorInfo()) && nonNull(right.getVendorInfo());
    }

    private boolean isOneMaskSetWhenOtherIsNull() {
        return (left.hasMask() && !right.hasMask()) || (!left.hasMask() && right.hasMask());
    }

    private boolean equalsInternal() {
        return Objects.equals(left.getVendorInfo(), right.getVendorInfo())
                && Objects.equals(left.getVendorInfoMask(), right.getVendorInfoMask());
    }

    private boolean equalsFromResponse() {
        final String mask = left.hasMask() ? left.getVendorInfoMask() : right.getVendorInfoMask();

        final String expected = applyMask(left, mask);
        final String actual = applyMask(right, mask);
        return expected.equals(actual);
    }

    private static String applyMask(MaskedVendorInfo maskedVendorInfo, String mask) {
        return MaskHelper.applyMask(maskedVendorInfo.getVendorInfo(), mask);
    }
}

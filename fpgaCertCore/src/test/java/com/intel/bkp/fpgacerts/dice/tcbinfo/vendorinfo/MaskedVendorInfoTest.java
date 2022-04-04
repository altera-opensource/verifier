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

package com.intel.bkp.fpgacerts.dice.tcbinfo.vendorinfo;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

class MaskedVendorInfoTest {

    private static final String VENDOR_INFO = "0011001100001111";
    private static final String VENDOR_INFO_MASK = "FFFFFFFF000000FF";
    private static final String VENDOR_INFO_RESPONSE_VALID = "0011001111111111";
    private static final String VENDOR_INFO_RESPONSE_INVALID = "0011001111111100";

    private final MaskedVendorInfo other = new MaskedVendorInfo(VENDOR_INFO, VENDOR_INFO_MASK);
    private final MaskedVendorInfo otherInvalidInfo = new MaskedVendorInfo("AAAA", VENDOR_INFO_MASK);
    private final MaskedVendorInfo otherInvalidMask = new MaskedVendorInfo(VENDOR_INFO, "AAAA");

    private final MaskedVendorInfo sut = new MaskedVendorInfo(VENDOR_INFO, VENDOR_INFO_MASK);

    @Test
    void equals_Basics() {
        // then
        Assertions.assertFalse(sut.equals(null));
        Assertions.assertTrue(sut.equals(sut));
        Assertions.assertFalse(sut.equals("ABC"));
    }

    @Test
    void equals_WithOtherNullVendorInfo_ReturnsFalse() {
        // then
        Assertions.assertFalse(sut.equals(new MaskedVendorInfo(null)));
        Assertions.assertFalse(new MaskedVendorInfo(null).equals(sut));
    }

    @Test
    void equals_WithOtherBothSetGood_ReturnsTrue() {
        // then
        Assertions.assertTrue(sut.equals(other));
        Assertions.assertTrue(other.equals(sut));
    }

    @Test
    void equals_WithOtherBothSetInvalidInfo_ReturnsFalse() {
        // then
        Assertions.assertFalse(sut.equals(otherInvalidInfo));
        Assertions.assertFalse(otherInvalidInfo.equals(sut));
    }

    @Test
    void equals_WithOtherBothSetInvalidMask_ReturnsFalse() {
        // then
        Assertions.assertFalse(sut.equals(otherInvalidMask));
        Assertions.assertFalse(otherInvalidMask.equals(sut));
    }

    @Test
    void equals_WithOtherBothSetNullMask_ReturnsTrue() {
        // then
        final MaskedVendorInfo left = new MaskedVendorInfo(VENDOR_INFO, null);
        final MaskedVendorInfo right = new MaskedVendorInfo(VENDOR_INFO, null);
        Assertions.assertTrue(left.equals(right));
        Assertions.assertTrue(right.equals(left));
    }

    @Test
    void equals_WithOtherBothSetNullInfo_ReturnsTrue() {
        // then
        final MaskedVendorInfo left = new MaskedVendorInfo(null, VENDOR_INFO_MASK);
        final MaskedVendorInfo right = new MaskedVendorInfo(null, VENDOR_INFO_MASK);
        Assertions.assertTrue(left.equals(right));
        Assertions.assertTrue(right.equals(left));
    }

    @Test
    void equals_FromResponse_ValidResponse_ReturnsTrue() {
        // then
        Assertions.assertTrue(sut.equals(new MaskedVendorInfo(VENDOR_INFO_RESPONSE_VALID)));
        Assertions.assertTrue(new MaskedVendorInfo(VENDOR_INFO_RESPONSE_VALID).equals(sut));
    }

    @Test
    void equals_FromResponse_InvalidResponse_ReturnsFalse() {
        // then
        Assertions.assertFalse(sut.equals(new MaskedVendorInfo(VENDOR_INFO_RESPONSE_INVALID)));
        Assertions.assertFalse(new MaskedVendorInfo(VENDOR_INFO_RESPONSE_INVALID).equals(sut));
    }

    @Test
    void toString_ReturnsValidString() {
        // given
        String expected = "MaskedVendorInfo( vendorInfo=0011001100001111 vendorInfoMask=FFFFFFFF000000FF )";

        // when
        final String result = sut.toString();

        // then
        Assertions.assertEquals(expected, result);
    }
}

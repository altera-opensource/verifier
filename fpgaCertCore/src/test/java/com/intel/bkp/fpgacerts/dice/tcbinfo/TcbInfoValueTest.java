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
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.junit.jupiter.MockitoExtension;

import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

@ExtendWith(MockitoExtension.class)
class TcbInfoValueTest {

    private static final String VERSION = "VERSION";
    private static final String DIFFERENT_VERSION = "DIFFERENT_VERSION";
    private static final int SVN = 3;
    private static final int DIFFERENT_SVN = SVN + 1;
    private static final FwIdField FWIDS = new FwIdField("HASH_ALG", "DIGEST");
    private static final FwIdField DIFFERENT_FWIDS = new FwIdField("HASH_ALG", "DIFFERENT_DIGEST");
    private static final MaskedVendorInfo VENDOR_INFO = new MaskedVendorInfo("VENDOR_INFO");
    private static final MaskedVendorInfo DIFFERENT_VENDOR_INFO = new MaskedVendorInfo("DIFFERENT_VENDOR_INFO");
    private static final String FLAGS = "80";
    private static final String DIFFERENT_FLAGS = "00";

    private static TcbInfo TCB_INFO;

    @BeforeAll
    static void init() {
        final var map = Map.of(
            TcbInfoField.VENDOR, TcbInfoConstants.VENDOR,
            TcbInfoField.MODEL, "MODEL",
            TcbInfoField.VERSION, VERSION,
            TcbInfoField.SVN, SVN,
            TcbInfoField.LAYER, 0,
            TcbInfoField.INDEX, 0,
            TcbInfoField.FWIDS, FWIDS,
            TcbInfoField.FLAGS, FLAGS,
            TcbInfoField.VENDOR_INFO, VENDOR_INFO,
            TcbInfoField.TYPE, "1.2.3.4"
        );
        TCB_INFO = new TcbInfo(map);
    }

    @Test
    void from_Empty() {
        // when
        final TcbInfoValue result = TcbInfoValue.from(new TcbInfo());

        // then
        assertTrue(result.getVersion().isEmpty());
        assertTrue(result.getSvn().isEmpty());
        assertTrue(result.getFwid().isEmpty());
        assertTrue(result.getMaskedVendorInfo().isEmpty());
        assertTrue(result.getFlags().isEmpty());
    }

    @Test
    void from_AllSet() {
        // when
        final TcbInfoValue result = TcbInfoValue.from(TCB_INFO);

        // then
        assertEquals(VERSION, result.getVersion().get());
        assertEquals(SVN, result.getSvn().get());
        assertEquals(FWIDS, result.getFwid().get());
        assertEquals(VENDOR_INFO, result.getMaskedVendorInfo().get());
        assertEquals(FLAGS, result.getFlags().get());
    }

    @Test
    void toString_Empty() {
        // given
        final String expected = "TcbInfoValue( )";

        // when
        final String result = TcbInfoValue.from(new TcbInfo()).toString();

        // then
        assertEquals(expected, result);
    }

    @Test
    void toString_AllSet() {
        // given
        final String expected = "TcbInfoValue( version=VERSION svn=3 fwid=FwIdField( hashAlg=HASH_ALG digest=DIGEST ) "
            + "maskedVendorInfo=MaskedVendorInfo( vendorInfo=VENDOR_INFO ) flags=80 )";

        // when
        final String result = TcbInfoValue.from(TCB_INFO).toString();

        // then
        assertEquals(expected, result);
    }

    @Test
    void matchesReferenceValue_Identical_ReturnsTrue() {
        // given
        final TcbInfoValue referenceValue = TcbInfoValue.from(TCB_INFO);
        final TcbInfoValue value = TcbInfoValue.from(TCB_INFO);

        // when-then
        assertTrue(value.matchesReferenceValue(referenceValue));
    }

    @Test
    void matchesReferenceValue_ReferenceEmpty_ReturnsTrue() {
        // given
        final TcbInfoValue referenceValue = new TcbInfoValue();
        final TcbInfoValue value = TcbInfoValue.from(TCB_INFO);

        // when-then
        assertTrue(value.matchesReferenceValue(referenceValue));
    }

    @Test
    void matchesReferenceValue_LessFieldsInValueThanInReference_ReturnsFalse() {
        // given
        final TcbInfoValue referenceValue = getTcbInfoValue(Map.of(
            TcbInfoField.FWIDS, FWIDS,
            TcbInfoField.VENDOR_INFO, VENDOR_INFO
        ));
        final TcbInfoValue value = getTcbInfoValue(Map.of(
            TcbInfoField.VENDOR_INFO, VENDOR_INFO
        ));

        // when-then
        assertFalse(value.matchesReferenceValue(referenceValue));
    }

    @Test
    void matchesReferenceValue_MoreFieldsInValueThanInReference_ReturnsTrue() {
        // given
        final TcbInfoValue referenceValue = getTcbInfoValue(Map.of(
            TcbInfoField.VENDOR_INFO, VENDOR_INFO
        ));
        final TcbInfoValue value = getTcbInfoValue(Map.of(
            TcbInfoField.FWIDS, FWIDS,
            TcbInfoField.VENDOR_INFO, VENDOR_INFO
        ));

        // when-then
        assertTrue(value.matchesReferenceValue(referenceValue));
    }

    @Test
    void matchesReferenceValue_NoVendorInfo_ReturnsFalse() {
        // given
        final TcbInfoValue referenceValue = getTcbInfoValue(Map.of(
            TcbInfoField.VENDOR_INFO, VENDOR_INFO
        ));
        final TcbInfoValue value = getTcbInfoValue(Map.of(
            TcbInfoField.FWIDS, FWIDS
        ));

        // when-then
        assertFalse(value.matchesReferenceValue(referenceValue));
    }

    @Test
    void matchesReferenceValue_DifferentVendorInfo_ReturnsFalse() {
        // given
        final TcbInfoValue referenceValue = getTcbInfoValue(Map.of(
            TcbInfoField.VENDOR_INFO, VENDOR_INFO
        ));
        final TcbInfoValue value = getTcbInfoValue(Map.of(
            TcbInfoField.VENDOR_INFO, DIFFERENT_VENDOR_INFO
        ));

        // when-then
        assertFalse(value.matchesReferenceValue(referenceValue));
    }

    @Test
    void matchesReferenceValue_DifferentFwIds_ReturnsFalse() {
        // given
        final TcbInfoValue referenceValue = getTcbInfoValue(Map.of(
            TcbInfoField.FWIDS, FWIDS
        ));
        final TcbInfoValue value = getTcbInfoValue(Map.of(
            TcbInfoField.FWIDS, DIFFERENT_FWIDS
        ));

        // when-then
        assertFalse(value.matchesReferenceValue(referenceValue));
    }

    @Test
    void matchesReferenceValue_DifferentSvn_ReturnsFalse() {
        // given
        final TcbInfoValue referenceValue = getTcbInfoValue(Map.of(
            TcbInfoField.SVN, SVN
        ));
        final TcbInfoValue value = getTcbInfoValue(Map.of(
            TcbInfoField.SVN, DIFFERENT_SVN
        ));

        // when-then
        assertFalse(value.matchesReferenceValue(referenceValue));
    }

    @Test
    void matchesReferenceValue_DifferentVersion_ReturnsFalse() {
        // given
        final TcbInfoValue referenceValue = getTcbInfoValue(Map.of(
            TcbInfoField.VERSION, VERSION
        ));
        final TcbInfoValue value = getTcbInfoValue(Map.of(
            TcbInfoField.VERSION, DIFFERENT_VERSION
        ));

        // when-then
        assertFalse(value.matchesReferenceValue(referenceValue));
    }

    @Test
    void matchesReferenceValue_DifferentFlags_ReturnsFalse() {
        // given
        final TcbInfoValue referenceValue = getTcbInfoValue(Map.of(
            TcbInfoField.FLAGS, FLAGS
        ));
        final TcbInfoValue value = getTcbInfoValue(Map.of(
            TcbInfoField.FLAGS, DIFFERENT_FLAGS
        ));

        // when-then
        assertFalse(value.matchesReferenceValue(referenceValue));
    }

    private TcbInfoValue getTcbInfoValue(Map<TcbInfoField, Object> map) {
        return TcbInfoValue.from(new TcbInfo(map));
    }
}

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

package com.intel.bkp.fpgacerts.dice.tcbinfo.verification;

import com.intel.bkp.fpgacerts.dice.tcbinfo.FwIdField;
import com.intel.bkp.fpgacerts.dice.tcbinfo.MeasurementType;
import com.intel.bkp.fpgacerts.dice.tcbinfo.TcbInfoConstants;
import com.intel.bkp.fpgacerts.dice.tcbinfo.TcbInfoKey;
import com.intel.bkp.fpgacerts.dice.tcbinfo.TcbInfoValue;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

import java.util.Map;
import java.util.Optional;

import static com.intel.bkp.fpgacerts.dice.tcbinfo.FwidHashAlg.FWIDS_HASH_ALG_SHA384;

class MeasurementExistenceVerifierTest {

    private static final MeasurementType MEASUREMENT_TYPE = MeasurementType.CMF;
    private static final MeasurementType DIFFERENT_MEASUREMENT_TYPE = MeasurementType.ROM_EXTENSION;
    private static final String DIFFERENT_VENDOR = "vendor";
    private static final String MODEL = "model";
    private static final String DIFFERENT_MODEL = "different model";
    private static final Integer DIFFERENT_INDEX = 3;
    private static final String DIFFERENT_HASH_ALG = "1.2.3";
    private static final TcbInfoValue VALUE_WITH_CORRECT_HASH_ALG = getValue(FWIDS_HASH_ALG_SHA384.getOid());
    private static final TcbInfoValue VALUE_WITH_DIFFERENT_HASH_ALG = getValue(DIFFERENT_HASH_ALG);

    private MeasurementExistenceVerifier sut;

    @Test
    void isMeasurementPresent_KeyForOlderDevices_ReturnsTrue() {
        // given
        final var map = Map.of(getKeyForOlderDevices(), VALUE_WITH_CORRECT_HASH_ALG);
        sut = MeasurementExistenceVerifier.instance(map);

        // when
        final boolean result = sut.isMeasurementPresent(MODEL, MEASUREMENT_TYPE);

        // then
        Assertions.assertTrue(result);
    }

    @Test
    void isMeasurementPresent_KeyForNewerDevices_ReturnsTrue() {
        // given
        final var map = Map.of(getKeyForNewerDevices(), VALUE_WITH_CORRECT_HASH_ALG);
        sut = MeasurementExistenceVerifier.instance(map);

        // when
        final boolean result = sut.isMeasurementPresent(MODEL, MEASUREMENT_TYPE);

        // then
        Assertions.assertTrue(result);
    }

    @Test
    void isMeasurementPresent_DifferentType_ReturnsFalse() {
        // given
        final var key = getKeyForOlderDevices();
        key.setType(DIFFERENT_MEASUREMENT_TYPE.getOid());
        final var map = Map.of(key, VALUE_WITH_CORRECT_HASH_ALG);
        sut = MeasurementExistenceVerifier.instance(map);

        // when
        final boolean result = sut.isMeasurementPresent(MODEL, MEASUREMENT_TYPE);

        // then
        Assertions.assertFalse(result);
    }

    @Test
    void isMeasurementPresent_DifferentModel_ReturnsFalse() {
        // given
        final var map = Map.of(getKeyForOlderDevices(), VALUE_WITH_CORRECT_HASH_ALG);
        sut = MeasurementExistenceVerifier.instance(map);

        // when
        final boolean result = sut.isMeasurementPresent(DIFFERENT_MODEL, MEASUREMENT_TYPE);

        // then
        Assertions.assertFalse(result);
    }

    @Test
    void isMeasurementPresent_DifferentLayer_ReturnsFalse() {
        // given
        final var key = getKeyForOlderDevices();
        key.setLayer(DIFFERENT_MEASUREMENT_TYPE.getLayer());
        final var map = Map.of(key, VALUE_WITH_CORRECT_HASH_ALG);
        sut = MeasurementExistenceVerifier.instance(map);

        // when
        final boolean result = sut.isMeasurementPresent(MODEL, MEASUREMENT_TYPE);

        // then
        Assertions.assertFalse(result);
    }

    @Test
    void isMeasurementPresent_DifferentVendorInMap_ReturnsFalse() {
        // given
        final var key = getKeyForOlderDevices();
        key.setVendor(DIFFERENT_VENDOR);
        final var map = Map.of(key, VALUE_WITH_CORRECT_HASH_ALG);
        sut = MeasurementExistenceVerifier.instance(map);

        // when
        final boolean result = sut.isMeasurementPresent(MODEL, MEASUREMENT_TYPE);

        // then
        Assertions.assertFalse(result);
    }

    @Test
    void isMeasurementPresent_DifferentIndexInMap_ReturnsFalse() {
        // given
        final var key = getKeyForOlderDevices();
        key.setIndex(DIFFERENT_INDEX);
        final var map = Map.of(key, VALUE_WITH_CORRECT_HASH_ALG);
        sut = MeasurementExistenceVerifier.instance(map);

        // when
        final boolean result = sut.isMeasurementPresent(MODEL, MEASUREMENT_TYPE);

        // then
        Assertions.assertFalse(result);
    }

    @Test
    void isMeasurementPresent_DifferentHashAlgInMap_ReturnsFalse() {
        // given
        final var map = Map.of(getKeyForOlderDevices(), VALUE_WITH_DIFFERENT_HASH_ALG);
        sut = MeasurementExistenceVerifier.instance(map);

        // when
        final boolean result = sut.isMeasurementPresent(MODEL, MEASUREMENT_TYPE);

        // then
        Assertions.assertFalse(result);
    }

    @Test
    void isMeasurementPresent_NoFwIdInValueInMap_ReturnsFalse() {
        // given
        final var map = Map.of(getKeyForOlderDevices(), new TcbInfoValue());
        sut = MeasurementExistenceVerifier.instance(map);

        // when
        final boolean result = sut.isMeasurementPresent(MODEL, MEASUREMENT_TYPE);

        // then
        Assertions.assertFalse(result);
    }

    private static TcbInfoKey getKeyForOlderDevices() {
        final var key = new TcbInfoKey();
        key.setVendor(TcbInfoConstants.VENDOR);
        key.setModel(MODEL);
        key.setLayer(MEASUREMENT_TYPE.getLayer());
        key.setIndex(TcbInfoConstants.INDEX);
        return key;
    }

    private static TcbInfoKey getKeyForNewerDevices() {
        final var key = new TcbInfoKey();
        key.setVendor(TcbInfoConstants.VENDOR);
        key.setType(MEASUREMENT_TYPE.getOid());
        key.setLayer(MEASUREMENT_TYPE.getLayer());
        return key;
    }

    private static TcbInfoValue getValue(String hashAlg) {
        final var fwId = new FwIdField();
        fwId.setHashAlg(hashAlg);

        final var value = new TcbInfoValue();
        value.setFwid(Optional.of(fwId));
        return value;
    }
}

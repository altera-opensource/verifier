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

import com.intel.bkp.fpgacerts.LogUtils;
import com.intel.bkp.fpgacerts.dice.tcbinfo.TcbInfoKey;
import com.intel.bkp.fpgacerts.dice.tcbinfo.TcbInfoValue;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.MockedStatic;
import org.mockito.junit.jupiter.MockitoExtension;
import uk.org.lidalia.slf4jext.Level;

import java.util.HashMap;
import java.util.Map;
import java.util.stream.Stream;

import static com.intel.bkp.fpgacerts.dice.tcbinfo.MeasurementType.CMF;
import static com.intel.bkp.fpgacerts.dice.tcbinfo.MeasurementType.ROM_EXTENSION;
import static org.mockito.Mockito.mockStatic;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class RequiredMeasurementsExistenceVerifierTest {

    private static final String FAMILY_NAME = "Family";
    private static final Map<TcbInfoKey, TcbInfoValue> MAP = new HashMap<>();

    private static final RequiredMeasurementsExistenceVerifier sut = new RequiredMeasurementsExistenceVerifier();

    private static MockedStatic<MeasurementExistenceVerifier> measurementExistenceVerifierMockStatic;

    @Mock
    private MeasurementExistenceVerifier existenceVerifier;

    @BeforeAll
    static void init() {
        sut.withFamilyName(FAMILY_NAME);
    }

    @BeforeAll
    static void prepareStaticMock() {
        measurementExistenceVerifierMockStatic = mockStatic(MeasurementExistenceVerifier.class);
    }

    @AfterEach
    void clearLogs() {
        LogUtils.clearLogs(sut.getClass());
    }

    @AfterAll
    static void closeStaticMock() {
        measurementExistenceVerifierMockStatic.close();
    }

    @Test
    void verify_AllRequiredExist_ReturnsTrue() {
        // given
        mockMeasurementExistenceVerifier(true, true);

        // when
        final boolean result = sut.verify(MAP);

        // then
        Assertions.assertTrue(result);
        Assertions.assertTrue(getErrorLogs().findAny().isEmpty());
    }

    @Test
    void verify_RomExtDoesNotExist_ReturnsFalseAndLogsError() {
        // given
        final String expectedMessage = "Chain does not contain all required measurements.\n"
            + "Is Rom extension measurement present: false\nIs CMF measurement present: true";
        mockMeasurementExistenceVerifier(false, true);

        // when
        final boolean result = sut.verify(MAP);

        // then
        Assertions.assertFalse(result);
        Assertions.assertTrue(getErrorLogs().anyMatch(message -> message.contains(expectedMessage)));
    }

    @Test
    void verify_CmfDoesNotExist_ReturnsFalseAndLogsError() {
        // given
        final String expectedMessage = "Chain does not contain all required measurements.\n"
            + "Is Rom extension measurement present: true\nIs CMF measurement present: false";
        mockMeasurementExistenceVerifier(true, false);

        // when
        final boolean result = sut.verify(MAP);

        // then
        Assertions.assertFalse(result);
        Assertions.assertTrue(getErrorLogs().anyMatch(message -> message.contains(expectedMessage)));
    }

    @Test
    void verify_NoneExist_ReturnsFalseAndLogsError() {
        // given
        final String expectedMessage = "Chain does not contain all required measurements.\n"
            + "Is Rom extension measurement present: false\nIs CMF measurement present: false";
        mockMeasurementExistenceVerifier(false, false);

        // when
        final boolean result = sut.verify(MAP);

        // then
        Assertions.assertFalse(result);
        Assertions.assertTrue(getErrorLogs().anyMatch(message -> message.contains(expectedMessage)));
    }

    private void mockMeasurementExistenceVerifier(boolean isRomExtPresent, boolean isCmfPresent) {
        when(MeasurementExistenceVerifier.instance(MAP)).thenReturn(existenceVerifier);
        when(existenceVerifier.isMeasurementPresent(FAMILY_NAME, ROM_EXTENSION)).thenReturn(isRomExtPresent);
        when(existenceVerifier.isMeasurementPresent(FAMILY_NAME, CMF)).thenReturn(isCmfPresent);
    }

    private Stream<String> getErrorLogs() {
        return LogUtils.getLogs(sut.getClass(), Level.ERROR);
    }
}

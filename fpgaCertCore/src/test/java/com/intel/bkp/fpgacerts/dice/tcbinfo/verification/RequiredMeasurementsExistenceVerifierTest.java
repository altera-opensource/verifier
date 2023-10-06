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

package com.intel.bkp.fpgacerts.dice.tcbinfo.verification;

import ch.qos.logback.classic.Level;
import com.intel.bkp.fpgacerts.LoggerTestUtil;
import com.intel.bkp.fpgacerts.dice.tcbinfo.TcbInfoKey;
import com.intel.bkp.fpgacerts.dice.tcbinfo.TcbInfoValue;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.MockedStatic;
import org.mockito.junit.jupiter.MockitoExtension;

import java.util.HashMap;
import java.util.Map;

import static com.intel.bkp.fpgacerts.dice.tcbinfo.MeasurementType.CMF;
import static com.intel.bkp.fpgacerts.dice.tcbinfo.MeasurementType.ROM_EXTENSION;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.mockStatic;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class RequiredMeasurementsExistenceVerifierTest {

    private LoggerTestUtil loggerTestUtil;

    private static final String FAMILY_NAME = "Family";
    private static final Map<TcbInfoKey, TcbInfoValue> MAP = new HashMap<>();

    private static final RequiredMeasurementsExistenceVerifier sut = new RequiredMeasurementsExistenceVerifier();

    private static MockedStatic<MeasurementExistenceVerifier> measurementExistenceVerifierMockStatic;

    @Mock
    private MeasurementExistenceVerifier existenceVerifier;

    @BeforeAll
    static void init() {
        sut.withFamilyName(FAMILY_NAME);
        measurementExistenceVerifierMockStatic = mockStatic(MeasurementExistenceVerifier.class);
    }

    @BeforeEach
    void setup() {
        loggerTestUtil = LoggerTestUtil.instance(sut.getClass());
    }

    @AfterEach
    void clearLogs() {
        loggerTestUtil.reset();
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
        assertTrue(result);
        assertEquals(0, loggerTestUtil.getSize());
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
        assertFalse(result);
        assertTrue(loggerTestUtil.contains(expectedMessage, Level.ERROR));
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
        assertFalse(result);
        assertTrue(loggerTestUtil.contains(expectedMessage, Level.ERROR));
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
        assertFalse(result);
        assertTrue(loggerTestUtil.contains(expectedMessage, Level.ERROR));
    }

    private void mockMeasurementExistenceVerifier(boolean isRomExtPresent, boolean isCmfPresent) {
        when(MeasurementExistenceVerifier.instance(MAP)).thenReturn(existenceVerifier);
        when(existenceVerifier.isMeasurementPresent(FAMILY_NAME, ROM_EXTENSION)).thenReturn(isRomExtPresent);
        when(existenceVerifier.isMeasurementPresent(FAMILY_NAME, CMF)).thenReturn(isCmfPresent);
    }
}

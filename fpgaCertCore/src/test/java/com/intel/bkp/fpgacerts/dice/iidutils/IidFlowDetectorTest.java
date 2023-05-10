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

package com.intel.bkp.fpgacerts.dice.iidutils;

import com.intel.bkp.fpgacerts.dice.ueid.UeidExtension;
import com.intel.bkp.fpgacerts.dice.ueid.UeidExtensionParser;
import com.intel.bkp.fpgacerts.model.AttFamily;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.security.cert.X509Certificate;
import java.util.Optional;

import static com.intel.bkp.fpgacerts.model.AttFamily.AGILEX;
import static com.intel.bkp.fpgacerts.model.AttFamily.EASIC_N5X;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class IidFlowDetectorTest {

    @Mock
    private X509Certificate cert;

    @Mock
    private UeidExtension ueidExtension;

    @Mock
    private UeidExtensionParser ueidExtensionParser;

    @Test
    void isIidFlow_RequireIidUdsTrue_Agilex_ReturnsTrue() {
        isIidFlow_ReturnsExpectedResult(Optional.of(true), AGILEX, true);
    }

    @Test
    void isIidFlow_RequireIidUdsTrue_NotAgilex_ReturnsFalse() {
        isIidFlow_ReturnsExpectedResult(Optional.of(true), EASIC_N5X, false);
    }

    @Test
    void isIidFlow_RequireIidUdsFalse_Agilex_ReturnsFalse() {
        isIidFlow_ReturnsExpectedResult(Optional.of(false), AGILEX, false);
    }

    @Test
    void isIidFlow_RequireIidUdsFalse_NotAgilex_ReturnsFalse() {
        isIidFlow_ReturnsExpectedResult(Optional.of(false), EASIC_N5X, false);
    }

    @Test
    void isIidFlow_RequireIidUdsNotSet_Agilex_ReturnsTrue() {
        isIidFlow_ReturnsExpectedResult(Optional.empty(), AGILEX, true);
    }

    @Test
    void isIidFlow_RequireIidUdsNotSet_NotAgilex_ReturnsFalse() {
        isIidFlow_ReturnsExpectedResult(Optional.empty(), EASIC_N5X, false);
    }

    @Test
    void isIidFlow_CertWithoutUeidExtension_Throws() {
        // given
        final IidFlowDetector sut = prepareSut(Optional.of(true));
        when(ueidExtensionParser.parse(cert)).thenThrow(new IllegalArgumentException(""));

        // when-then
        Assertions.assertThrows(IllegalArgumentException.class, () -> sut.isIidFlow(cert));
    }

    private void isIidFlow_ReturnsExpectedResult(Optional<Boolean> requireIidUds, AttFamily family,
                                                 boolean expectedResult) {
        // given
        final IidFlowDetector sut = prepareSut(requireIidUds);
        if (requireIidUds.isEmpty() || requireIidUds.get()) {
            mockUeidExtension(family);
        }

        // when
        final boolean result = sut.isIidFlow(cert);

        // then
        Assertions.assertEquals(expectedResult, result);
    }

    private IidFlowDetector prepareSut(Optional<Boolean> requireIidUds) {
        final var iidFlowDetector = new IidFlowDetector(ueidExtensionParser);
        requireIidUds.ifPresent(iidFlowDetector::withRequireIidUds);
        return iidFlowDetector;
    }

    private void mockUeidExtension(AttFamily family) {
        when(ueidExtensionParser.parse(cert)).thenReturn(ueidExtension);
        when(ueidExtension.getFamilyId()).thenReturn(family.getFamilyId());
    }
}

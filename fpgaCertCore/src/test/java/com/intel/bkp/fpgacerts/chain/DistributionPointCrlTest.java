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

package com.intel.bkp.fpgacerts.chain;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.security.cert.X509CRL;
import java.util.Collection;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertIterableEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

@ExtendWith(MockitoExtension.class)
class DistributionPointCrlTest {

    private static final String URL_1 = "first URL";
    private static final String URL_2 = "second URL";

    @Mock
    private X509CRL crl_1;

    @Mock
    private X509CRL crl_2;

    private Collection<DistributionPointCrl> dpCrls;

    @BeforeEach
    void initCollection() {
        dpCrls = List.of(new DistributionPointCrl(URL_1, crl_1), new DistributionPointCrl(URL_2, crl_2));
    }

    @Test
    void getX509Crls_Success() {
        // given
        final var x509Crls = List.of(crl_1, crl_2);

        // when
        final var result = DistributionPointCrl.getX509Crls(dpCrls);

        // then
        assertIterableEquals(x509Crls, result);
    }

    @Test
    void getX509Crls_EmptyCollection_ReturnsEmptyList() {
        // when
        final var result = DistributionPointCrl.getX509Crls(List.of());

        // then
        assertNotNull(result);
        assertTrue(result.isEmpty());
    }

    @Test
    void getX509Crls_NullCollection_ThrowsNullPointer() {
        // when-then
        assertThrows(NullPointerException.class, () -> DistributionPointCrl.getX509Crls(null));
    }

    @Test
    void toMap_Success() {
        // given
        final var crlMap = Map.of(URL_1, crl_1, URL_2, crl_2);

        // when
        final var result = DistributionPointCrl.toMap(dpCrls);

        // then
        assertEquals(crlMap, result);
    }

    @Test
    void toMap_EmptyCollection_ReturnsEmptyMap() {
        // when
        final var result = DistributionPointCrl.toMap(List.of());

        // then
        assertNotNull(result);
        assertTrue(result.isEmpty());
    }

    @Test
    void toMap_NullCollection_ThrowsNullPointer() {
        // when-then
        assertThrows(NullPointerException.class, () -> DistributionPointCrl.toMap(null));
    }
}

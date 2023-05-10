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

package com.intel.bkp.verifier.service.measurements;

import ch.qos.logback.classic.Level;
import com.intel.bkp.fpgacerts.dice.tcbinfo.FwIdField;
import com.intel.bkp.fpgacerts.dice.tcbinfo.TcbInfo;
import com.intel.bkp.fpgacerts.dice.tcbinfo.TcbInfoField;
import com.intel.bkp.fpgacerts.dice.tcbinfo.TcbInfoKey;
import com.intel.bkp.fpgacerts.dice.tcbinfo.TcbInfoMeasurement;
import com.intel.bkp.fpgacerts.dice.tcbinfo.TcbInfoMeasurementsAggregator;
import com.intel.bkp.fpgacerts.dice.tcbinfo.TcbInfoValue;
import com.intel.bkp.fpgacerts.dice.tcbinfo.vendorinfo.MaskedVendorInfo;
import com.intel.bkp.verifier.LoggerTestUtil;
import com.intel.bkp.verifier.model.VerifierExchangeResponse;
import com.intel.bkp.verifier.model.evidence.Rim;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import static ch.qos.logback.classic.Level.DEBUG;
import static ch.qos.logback.classic.Level.INFO;
import static ch.qos.logback.classic.Level.WARN;
import static com.intel.bkp.verifier.model.VerifierExchangeResponse.ERROR;
import static com.intel.bkp.verifier.model.VerifierExchangeResponse.FAIL;
import static com.intel.bkp.verifier.model.VerifierExchangeResponse.OK;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class EvidenceVerifierTest {

    private static final String REF_MEASUREMENT = "test";
    private static final String VENDOR = "VENDOR";
    private static final String VENDOR_INFO = "0000000003000000";
    private static final String VENDOR_INFO_INVALID = "1111111111111111";
    private static final String VENDOR_INFO_MASK = "FFFFFFFF000000FF";
    private static final String MODEL = "Agilex";
    private static final int INDEX = 0;
    private static final int LAYER = 1;
    private static final String HASH_ALG = "HASHALG";
    private static final String FWID_DIGEST = "DIGEST";
    private static final String OWNER_SECURITY_FUSES_TYPE = "6086480186F84D010F0411";

    private final Map<TcbInfoKey, TcbInfoValue> tcbInfoResponseMap = new HashMap<>();

    @Mock
    private Rim rim;

    @Mock
    private TcbInfoMeasurementsAggregator tcbInfoMeasurementsAggregator;

    @Mock
    private RimParser rimParser;

    @Mock
    private RimToTcbInfoMeasurementsMapper rimMapper;

    @InjectMocks
    private EvidenceVerifier sut;

    private LoggerTestUtil loggerTestUtil;

    @BeforeEach
    void setUpClass() {
        loggerTestUtil = LoggerTestUtil.instance(sut.getClass());
    }

    @AfterEach
    void clearLogs() {
        loggerTestUtil.reset();
    }

    @Test
    void verify_WithEmptyRim_ReturnsOk() {
        // given
        when(rimParser.parse(REF_MEASUREMENT)).thenReturn(mockEmptyRim());

        // when
        final VerifierExchangeResponse result = sut.verify(tcbInfoMeasurementsAggregator, REF_MEASUREMENT);

        // then
        assertEquals(OK, result);
        verifyLogExists("List of expected measurements in RIM is empty.", WARN);
    }

    @Test
    void verify_ThrowsException_ReturnsError() {
        // given
        doThrow(new IllegalArgumentException()).when(rimParser).parse(REF_MEASUREMENT);

        // when
        final VerifierExchangeResponse result = sut.verify(tcbInfoMeasurementsAggregator, REF_MEASUREMENT);

        // then
        assertEquals(ERROR, result);
    }

    @Test
    void verify_ResponseContainsExactlyTheSameMeasurementsAsReference_ReturnsOk() {
        // given
        final var tcbInfo = prepareTcbInfoWithOwnerSecurityFuses(VENDOR_INFO);
        final var key = TcbInfoKey.from(tcbInfo);
        final var value = TcbInfoValue.from(tcbInfo);
        when(rimParser.parse(REF_MEASUREMENT)).thenReturn(rim);
        when(rimMapper.map(rim)).thenReturn(prepareReferenceMeasurements(tcbInfo));
        mockResponse(tcbInfo);

        // when
        final VerifierExchangeResponse result = sut.verify(tcbInfoMeasurementsAggregator, REF_MEASUREMENT);

        // then
        assertEquals(OK, result);
        verifyLogExists("Verification of measurement: %s".formatted(key), INFO);
        verifyLogExists("Reference value: %s".formatted(value), DEBUG);
        verifyLogExists("Received value: %s".formatted(value), DEBUG);
        verifyLogExists("Verification passed.", INFO);
    }

    @Test
    void verify_ResponseContainsMoreMeasurementsThanReference_ReturnsOk() {
        // given
        final var tcbInfo1Masked = prepareTcbInfoWithOwnerSecurityFusesMasked(VENDOR_INFO);
        final var tcbInfo1 = prepareTcbInfoWithOwnerSecurityFuses(VENDOR_INFO);
        final var tcbInfo2 = prepareTcbInfoWithFwId();
        when(rimParser.parse(REF_MEASUREMENT)).thenReturn(rim);
        when(rimMapper.map(rim)).thenReturn(prepareReferenceMeasurements(tcbInfo1Masked));
        mockResponse(tcbInfo1, tcbInfo2);

        // when
        final VerifierExchangeResponse result = sut.verify(tcbInfoMeasurementsAggregator, REF_MEASUREMENT);

        // then
        assertEquals(OK, result);
        verifyLogExists("Verification of measurement: %s".formatted(TcbInfoKey.from(tcbInfo1Masked)), INFO);
        verifyLogDoesNotExist("Verification of measurement: %s".formatted(TcbInfoKey.from(tcbInfo2)), INFO);
    }

    @Test
    void verify_MeasurementInResponseContainsAdditionalValueNotPresentInReferenceMeasurement_ReturnsOk() {
        // given
        final var tcbInfo = prepareTcbInfoWithFwId();
        final var tcbInfoWithAdditionalValue = prepareTcbInfoWithFwIdAndAdditionalVendorInfo();
        when(rimParser.parse(REF_MEASUREMENT)).thenReturn(rim);
        when(rimMapper.map(rim)).thenReturn(prepareReferenceMeasurements(tcbInfo));
        mockResponse(tcbInfoWithAdditionalValue);

        // when
        final VerifierExchangeResponse result = sut.verify(tcbInfoMeasurementsAggregator, REF_MEASUREMENT);

        // then
        assertEquals(OK, result);
        verifyLogExists("Reference value: %s".formatted(TcbInfoValue.from(tcbInfo)), DEBUG);
        verifyLogExists("Received value: %s".formatted(TcbInfoValue.from(tcbInfoWithAdditionalValue)), DEBUG);
    }

    @Test
    void verify_MeasurementInResponseDoesNotContainAdditionalValuePresentInReferenceMeasurement_ReturnsFail() {
        // given
        final var tcbInfo = prepareTcbInfoWithFwId();
        final var tcbInfoWithAdditionalValue = prepareTcbInfoWithFwIdAndAdditionalVendorInfo();
        when(rimParser.parse(REF_MEASUREMENT)).thenReturn(rim);
        when(rimMapper.map(rim)).thenReturn(prepareReferenceMeasurements(tcbInfoWithAdditionalValue));
        mockResponse(tcbInfo);

        // when
        final VerifierExchangeResponse result = sut.verify(tcbInfoMeasurementsAggregator, REF_MEASUREMENT);

        // then
        assertEquals(FAIL, result);
        verifyLogExists("Evidence verification failed.\nReference: %s\nActual:    %s".formatted(
                TcbInfoValue.from(tcbInfoWithAdditionalValue),
                TcbInfoValue.from(tcbInfo)),
            Level.ERROR);
    }

    @Test
    void verify_MissingMeasurementInResponse_ReturnsFail() {
        // given
        final var tcbInfo = prepareTcbInfoWithOwnerSecurityFuses(VENDOR_INFO);
        when(rimParser.parse(REF_MEASUREMENT)).thenReturn(rim);
        when(rimMapper.map(rim)).thenReturn(prepareReferenceMeasurements(tcbInfo));

        // when
        final VerifierExchangeResponse result = sut.verify(tcbInfoMeasurementsAggregator, REF_MEASUREMENT);

        // then
        assertEquals(FAIL, result);
        verifyLogExists("Evidence verification failed. Response does not contain expected key.", Level.ERROR);
    }

    @Test
    void verify_MeasurementInResponseHasValueNotMatchingReferenceValue_ReturnsFail() {
        // given
        final var tcbInfo = prepareTcbInfoWithOwnerSecurityFuses(VENDOR_INFO);
        final var tcbInfoWithDiffValue = prepareTcbInfoWithOwnerSecurityFuses(VENDOR_INFO_INVALID);
        when(rimParser.parse(REF_MEASUREMENT)).thenReturn(rim);
        when(rimMapper.map(rim)).thenReturn(prepareReferenceMeasurements(tcbInfo));
        mockResponse(tcbInfoWithDiffValue);

        // when
        final VerifierExchangeResponse result = sut.verify(tcbInfoMeasurementsAggregator, REF_MEASUREMENT);

        // then
        assertEquals(FAIL, result);
        verifyLogExists("Evidence verification failed.\nReference: %s\nActual:    %s".formatted(
                TcbInfoValue.from(tcbInfo),
                TcbInfoValue.from(tcbInfoWithDiffValue)),
            Level.ERROR);
    }

    private Rim mockEmptyRim() {
        return new Rim();
    }

    private List<TcbInfoMeasurement> prepareReferenceMeasurements(TcbInfo... tcbInfos) {
        return Arrays.stream(tcbInfos).map(TcbInfoMeasurement::new).toList();
    }

    private void mockResponse(TcbInfo... tcbInfos) {
        tcbInfoResponseMap.clear();
        for (final TcbInfo tcbInfo : tcbInfos) {
            tcbInfoResponseMap.put(TcbInfoKey.from(tcbInfo), TcbInfoValue.from(tcbInfo));
        }
        when(tcbInfoMeasurementsAggregator.getMap()).thenReturn(tcbInfoResponseMap);
    }

    private TcbInfo prepareTcbInfoWithOwnerSecurityFusesMasked(String ownerSecurityFuses) {
        return prepareTcbInfoWithOwnerSecurityFuses(new MaskedVendorInfo(ownerSecurityFuses, VENDOR_INFO_MASK));
    }

    private TcbInfo prepareTcbInfoWithOwnerSecurityFuses(String ownerSecurityFuses) {
        return prepareTcbInfoWithOwnerSecurityFuses(new MaskedVendorInfo(ownerSecurityFuses));
    }

    private TcbInfo prepareTcbInfoWithOwnerSecurityFuses(MaskedVendorInfo vendorInfo) {
        final Map<TcbInfoField, Object> map = Map.of(
            TcbInfoField.VENDOR, VENDOR,
            TcbInfoField.LAYER, LAYER,
            TcbInfoField.VENDOR_INFO, vendorInfo,
            TcbInfoField.TYPE, OWNER_SECURITY_FUSES_TYPE
        );
        return new TcbInfo(map);
    }

    private TcbInfo prepareTcbInfoWithFwId() {
        final var map = Map.of(
            TcbInfoField.VENDOR, VENDOR,
            TcbInfoField.MODEL, MODEL,
            TcbInfoField.LAYER, LAYER,
            TcbInfoField.INDEX, INDEX,
            TcbInfoField.FWIDS, new FwIdField(HASH_ALG, FWID_DIGEST)
        );
        return new TcbInfo(map);
    }

    private TcbInfo prepareTcbInfoWithFwIdAndAdditionalVendorInfo() {
        final var map = Map.of(
            TcbInfoField.VENDOR, VENDOR,
            TcbInfoField.MODEL, MODEL,
            TcbInfoField.LAYER, LAYER,
            TcbInfoField.INDEX, INDEX,
            TcbInfoField.FWIDS, new FwIdField(HASH_ALG, FWID_DIGEST),
            TcbInfoField.VENDOR_INFO, VENDOR_INFO
        );
        return new TcbInfo(map);
    }

    private void verifyLogExists(String log, Level level) {
        assertTrue(loggerTestUtil.contains(log, level));
    }

    private void verifyLogDoesNotExist(String log, Level level) {
        assertFalse(loggerTestUtil.contains(log, level));
    }
}

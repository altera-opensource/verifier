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

package com.intel.bkp.core.psgcertificate;

import com.intel.bkp.core.endianess.EndianessActor;
import com.intel.bkp.core.psgcertificate.exceptions.PsgCertificateException;
import com.intel.bkp.core.psgcertificate.model.CertificateEntryWrapper;
import com.intel.bkp.core.psgcertificate.model.PsgCertificateType;
import com.intel.bkp.core.psgcertificate.model.PsgCurveType;
import com.intel.bkp.core.psgcertificate.model.PsgPublicKeyMagic;
import com.intel.bkp.core.psgcertificate.model.PsgRootHashType;
import com.intel.bkp.core.psgcertificate.model.PsgSignatureCurveType;
import com.intel.bkp.crypto.constants.CryptoConstants;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

import java.nio.ByteBuffer;
import java.security.KeyPair;
import java.security.interfaces.ECPublicKey;
import java.util.List;

import static com.intel.bkp.core.TestUtil.genEcKeys;
import static com.intel.bkp.core.TestUtil.signEcData;
import static com.intel.bkp.utils.HexConverter.toHex;

class PsgCertificateForBkpsAdapterTest {

    @Test
    void parse_WithOnlyLeafCertificate_Success() throws PsgCertificateException {
        // given
        byte[] result = prepareLeafPsgCertificate();

        // when
        final List<CertificateEntryWrapper> parse = PsgCertificateForBkpsAdapter
            .parse(toHex(result));

        // then
        Assertions.assertFalse(parse.isEmpty());
    }

    @Test
    void parse_WithOnlyRootCertificate_Success() throws PsgCertificateException {
        // given
        byte[] result = prepareRootPsgCertificate();

        // when
        final List<CertificateEntryWrapper> parse = PsgCertificateForBkpsAdapter
            .parse(toHex(result));

        // then
        Assertions.assertFalse(parse.isEmpty());
    }

    @Test
    void parse_WithCertificateChain_Success() throws PsgCertificateException {
        // given
        final byte[] rootCertificate = prepareRootPsgCertificate();
        final byte[] leafCertificate = prepareLeafPsgCertificate();

        final ByteBuffer buffer = ByteBuffer.allocate(rootCertificate.length + leafCertificate.length);
        buffer.put(rootCertificate);
        buffer.put(leafCertificate);
        String testData = toHex(buffer.array());

        // when
        final List<CertificateEntryWrapper> parse = PsgCertificateForBkpsAdapter.parse(testData);

        // then
        Assertions.assertFalse(parse.isEmpty());
        Assertions.assertEquals(2, parse.size());
        Assertions.assertEquals(1, parse
            .stream()
            .filter(wrapper -> wrapper.getType().equals(PsgCertificateType.ROOT))
            .count()
        );
        Assertions.assertEquals(1, parse
            .stream()
            .filter(wrapper -> wrapper.getType().equals(PsgCertificateType.LEAF))
            .count()
        );
    }

    @Test
    void parse_withWrongData_ReturnsEmptyList() throws PsgCertificateException {
        // given
        ByteBuffer buffer = ByteBuffer.allocate(3 * Integer.BYTES);
        buffer.putInt(1);
        buffer.putInt(2);
        buffer.putInt(3);
        final String testData = toHex(buffer.array());

        // when
        final List<CertificateEntryWrapper> parse = PsgCertificateForBkpsAdapter.parse(testData);

        // then
        Assertions.assertTrue(parse.isEmpty());
    }

    private byte[] prepareLeafPsgCertificate() throws PsgCertificateException {
        KeyPair keyPair = genEcKeys(null);
        assert keyPair != null;

        PsgPublicKeyBuilder psgPublicKeyBuilder = getPsgPublicKeyBuilder(keyPair, PsgCurveType.SECP384R1);
        PsgSignatureBuilder psgSignatureBuilder = getPsgSignatureBuilder(PsgSignatureCurveType.SECP384R1);

        return new PsgCertificateEntryBuilder()
            .publicKey(psgPublicKeyBuilder)
            .withSignature(psgSignatureBuilder)
            .signData(dataToSign -> signEcData(dataToSign, keyPair.getPrivate(), CryptoConstants.SHA384_WITH_ECDSA))
            .withActor(EndianessActor.FIRMWARE)
            .build()
            .array();
    }

    private byte[] prepareRootPsgCertificate() throws PsgCertificateException {
        KeyPair keyPair = genEcKeys(CryptoConstants.EC_CURVE_SPEC_384);
        assert keyPair != null;

        PsgPublicKeyBuilder psgPublicKeyBuilder = getPsgPublicKeyBuilder(keyPair, PsgCurveType.SECP384R1);

        return new PsgCertificateRootEntryBuilder()
            .rootHashType(PsgRootHashType.MANUFACTURING)
            .publicKey(psgPublicKeyBuilder)
            .withActor(EndianessActor.FIRMWARE)
            .build().array();
    }

    private PsgPublicKeyBuilder getPsgPublicKeyBuilder(KeyPair keyPair, PsgCurveType psgCurveType) {
        return new PsgPublicKeyBuilder()
            .magic(PsgPublicKeyMagic.M1_MAGIC)
            .curveType(psgCurveType)
            .publicKey((ECPublicKey) keyPair.getPublic());
    }

    private PsgSignatureBuilder getPsgSignatureBuilder(PsgSignatureCurveType psgSignatureCurveType) {
        return new PsgSignatureBuilder()
            .signatureType(psgSignatureCurveType);
    }
}

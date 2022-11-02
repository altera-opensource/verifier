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

package com.intel.bkp.core;

import com.intel.bkp.core.endianess.EndianessActor;
import com.intel.bkp.core.psgcertificate.PsgCancellableBlock0EntryBuilder;
import com.intel.bkp.core.psgcertificate.PsgCertificateEntryBuilder;
import com.intel.bkp.core.psgcertificate.PsgCertificateRootEntryBuilder;
import com.intel.bkp.core.psgcertificate.PsgPublicKeyBuilder;
import com.intel.bkp.core.psgcertificate.PsgSignatureBuilder;
import com.intel.bkp.core.psgcertificate.model.CertificateEntryWrapper;
import com.intel.bkp.core.psgcertificate.model.PsgCertificateType;
import com.intel.bkp.core.psgcertificate.model.PsgCurveType;
import com.intel.bkp.core.psgcertificate.model.PsgPublicKeyMagic;
import com.intel.bkp.core.psgcertificate.model.PsgSignatureCurveType;
import com.intel.bkp.crypto.constants.CryptoConstants;
import lombok.SneakyThrows;
import org.apache.commons.lang3.ArrayUtils;

import java.nio.ByteBuffer;
import java.security.KeyPair;
import java.security.interfaces.ECPublicKey;
import java.util.ArrayList;
import java.util.Collections;
import java.util.LinkedList;
import java.util.List;

public class RomExtensionAuthGeneratorUtil {

    KeyPair rootKeyPair = TestUtil.genEcKeys();
    KeyPair leafKeyPair = TestUtil.genEcKeys();

    public byte[] signRomExtension(byte[] dataToSign) {
        byte[] parentKeyChain = getChain(getMultiCertChain());
        byte[] block0Entry = getCancellableBlock0Entry(leafKeyPair, dataToSign);
        return ArrayUtils.addAll(parentKeyChain, block0Entry);
    }

    @SneakyThrows
    public List<CertificateEntryWrapper> getMultiCertChain() {
        // given
        assert rootKeyPair != null;
        assert leafKeyPair != null;

        List<CertificateEntryWrapper> certificateChainList = new LinkedList<>();

        byte[] rootContent = new PsgCertificateRootEntryBuilder()
            .asMultiRoot()
            .publicKey(getPsgPublicKeyBuilder(rootKeyPair))
            .build()
            .array();
        certificateChainList.add(new CertificateEntryWrapper(PsgCertificateType.ROOT, rootContent));

        byte[] leafContent = new PsgCertificateEntryBuilder()
            .withSignature(getPsgSignatureBuilder())
            .publicKey(getPsgPublicKeyBuilder(leafKeyPair))
            .signData(dataToSign -> TestUtil.signEcData(
                dataToSign, rootKeyPair.getPrivate(), CryptoConstants.SHA384_WITH_ECDSA)
            )
            .build()
            .array();
        certificateChainList.add(new CertificateEntryWrapper(PsgCertificateType.LEAF, leafContent));
        return certificateChainList;
    }

    private byte[] getCancellableBlock0Entry(KeyPair keyPair, byte[] dataToSign) {
        final var builder = new PsgCancellableBlock0EntryBuilder();
        byte[] customDataToSign = builder.getCustomPayloadForSignature(dataToSign);
        byte[] signedData = TestUtil.signEcData(
            customDataToSign, keyPair.getPrivate(), CryptoConstants.SHA384_WITH_ECDSA
        );
        return builder
            .withActor(EndianessActor.FIRMWARE)
            .signature(signedData)
            .build()
            .array();
    }

    private byte[] getChain(List<CertificateEntryWrapper> certificateChainList) {
        if (!PsgCertificateType.ROOT.equals(certificateChainList.get(0).getType())) {
            Collections.reverse(certificateChainList); // makes ROOT first
        }

        List<byte[]> certContentSwapped = getCertContentSwapped(certificateChainList);

        int sum = certContentSwapped.stream().mapToInt(c -> c.length).sum();

        final ByteBuffer byteBuffer = ByteBuffer.allocate(sum);
        certContentSwapped.forEach(byteBuffer::put);
        return byteBuffer.array();
    }

    private List<byte[]> getCertContentSwapped(List<CertificateEntryWrapper> certificateChainList) {
        final List<byte[]> certificateChainSwapped = new ArrayList<>();

        certificateChainList.forEach(c -> {
            if (PsgCertificateType.ROOT.equals(c.getType())) {
                certificateChainSwapped.add(getRootContentSwapped(c.getContent()));
            } else if (PsgCertificateType.LEAF.equals(c.getType())) {
                certificateChainSwapped.add(getLeafContentSwapped(c.getContent()));
            }
        });
        return certificateChainSwapped;
    }

    @SneakyThrows
    private byte[] getRootContentSwapped(byte[] content) {
        return new PsgCertificateRootEntryBuilder().parse(content)
            .withActor(EndianessActor.FIRMWARE).build().array();
    }

    @SneakyThrows
    private byte[] getLeafContentSwapped(byte[] content) {
        return new PsgCertificateEntryBuilder().parse(content)
            .withActor(EndianessActor.FIRMWARE).build().array();
    }

    private PsgPublicKeyBuilder getPsgPublicKeyBuilder(KeyPair keyPair) {
        return new PsgPublicKeyBuilder()
            .magic(PsgPublicKeyMagic.M1_MAGIC)
            .curveType(PsgCurveType.SECP384R1)
            .publicKey((ECPublicKey) keyPair.getPublic());
    }

    private PsgSignatureBuilder getPsgSignatureBuilder() {
        return new PsgSignatureBuilder()
            .signatureType(PsgSignatureCurveType.SECP384R1);
    }
}

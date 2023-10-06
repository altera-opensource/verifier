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

package com.intel.bkp.test.rim;

import com.intel.bkp.fpgacerts.cbor.ProtectedHeaderType;
import com.intel.bkp.fpgacerts.cbor.rim.ProtectedSignersItem;
import com.intel.bkp.fpgacerts.cbor.signer.CborSignatureVerifier;
import com.intel.bkp.fpgacerts.cbor.signer.CoseMessage1Signer;
import com.intel.bkp.fpgacerts.cbor.signer.cose.CborKeyPair;
import com.intel.bkp.fpgacerts.cbor.signer.cose.model.AlgorithmId;
import com.intel.bkp.fpgacerts.cbor.xrim.XrimEntityMap;
import com.intel.bkp.fpgacerts.cbor.xrim.XrimProtectedHeader;
import com.intel.bkp.fpgacerts.cbor.xrim.XrimProtectedMetaMap;
import com.intel.bkp.fpgacerts.cbor.xrim.XrimUnsigned;
import com.intel.bkp.fpgacerts.cbor.xrim.builder.XrimUnsignedBuilder;
import com.intel.bkp.test.RandomUtils;
import lombok.AccessLevel;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;
import lombok.SneakyThrows;
import lombok.experimental.Accessors;

import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.List;

import static com.intel.bkp.test.rim.RimGenerator.ISSUER_KEY_LEN;

@NoArgsConstructor(access = AccessLevel.PRIVATE)
@Setter
@Getter
@Accessors(fluent = true)
public class XrimGenerator {

    private static final CborSignatureVerifier CBOR_SIGNATURE_VERIFIER = new CborSignatureVerifier();

    private boolean signed = true;
    private boolean design = false;
    private PrivateKey privateKey;
    private PublicKey publicKey;
    private String denyItemId = "51ac25b8dc58405cb4c94772120ba68a";

    public static XrimGenerator instance() {
        return new XrimGenerator();
    }

    public XrimGenerator keyPair(KeyPair keyPair) {
        this.privateKey = keyPair.getPrivate();
        this.publicKey = keyPair.getPublic();
        return this;
    }

    public byte[] generate() {
        if (signed()) {
            return generateSigned();
        } else {
            return generateStandaloneUnsigned();
        }
    }

    @SneakyThrows
    private byte[] generateSigned() {
        final CborKeyPair signingKey = CborKeyPair.fromKeyPair(publicKey, privateKey);

        final byte[] payload = prepareUnsignedXrim();
        final var protectedHeader = prepareProtectedHeader(AlgorithmId.ECDSA_384);
        final byte[] signed = CoseMessage1Signer.instance().sign(signingKey, payload, protectedHeader);

        final boolean verified = CBOR_SIGNATURE_VERIFIER.verify(signingKey.getPublicKey(), signed);
        assert verified : "Cbor signature verification failed after signing structure";

        return signed;
    }

    private byte[] generateStandaloneUnsigned() {
        final var xrimUnsignedGeneric = XrimUnsigned.builder()
            .entityMaps(prepareEntityMaps())
            .denyList(List.of(denyItemId))
            .build();

        return XrimUnsignedBuilder.instance()
            .standalone()
            .build(xrimUnsignedGeneric);
    }

    private byte[] prepareUnsignedXrim() {
        final var xrimUnsignedGeneric = XrimUnsigned.builder()
            .entityMaps(prepareEntityMaps())
            .denyList(List.of(denyItemId))
            .build();

        return XrimUnsignedBuilder.instance().build(xrimUnsignedGeneric);
    }

    private List<XrimEntityMap> prepareEntityMaps() {
        return List.of(XrimEntityMap.builder()
            .entityName(prepareEntityName())
            .regId("")
            .roles(List.of(1))
            .build());
    }

    private XrimProtectedHeader prepareProtectedHeader(AlgorithmId algorithmId) {
        return XrimProtectedHeader.builder()
            .algorithmId(algorithmId)
            .contentType(ProtectedHeaderType.XRIM.getContentType())
            .issuerKeyId(RandomUtils.generateRandomHex(ISSUER_KEY_LEN))
            .metaMap(prepareProtectedMetaMap())
            .build();
    }

    private XrimProtectedMetaMap prepareProtectedMetaMap() {
        return XrimProtectedMetaMap.builder()
            .metaItem(ProtectedSignersItem.builder().entityName(prepareEntityName()).build())
            .issuedDate(Instant.now().minus(5, ChronoUnit.MINUTES))
            .build();
    }

    private String prepareEntityName() {
        return design() ? "XCorim Owner" : "Firmware Author";
    }
}

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

import com.intel.bkp.crypto.curve.CurvePoint;
import com.intel.bkp.fpgacerts.cbor.LocatorItem;
import com.intel.bkp.fpgacerts.cbor.LocatorType;
import com.intel.bkp.fpgacerts.cbor.ProtectedHeaderType;
import com.intel.bkp.fpgacerts.cbor.rim.Comid;
import com.intel.bkp.fpgacerts.cbor.rim.ProtectedMetaMap;
import com.intel.bkp.fpgacerts.cbor.rim.ProtectedSignersItem;
import com.intel.bkp.fpgacerts.cbor.rim.RimProtectedHeader;
import com.intel.bkp.fpgacerts.cbor.rim.RimUnsigned;
import com.intel.bkp.fpgacerts.cbor.rim.builder.RimUnsignedBuilder;
import com.intel.bkp.fpgacerts.cbor.rim.comid.Claims;
import com.intel.bkp.fpgacerts.cbor.rim.comid.ComidEntity;
import com.intel.bkp.fpgacerts.cbor.rim.comid.ComidId;
import com.intel.bkp.fpgacerts.cbor.rim.comid.ReferenceTriple;
import com.intel.bkp.fpgacerts.cbor.signer.CborSignatureVerifier;
import com.intel.bkp.fpgacerts.cbor.signer.CoseMessage1Signer;
import com.intel.bkp.fpgacerts.cbor.signer.cose.CborKeyPair;
import com.intel.bkp.fpgacerts.cbor.signer.cose.model.AlgorithmId;
import com.intel.bkp.fpgacerts.model.Family;
import com.intel.bkp.fpgacerts.utils.SkiHelper;
import com.intel.bkp.utils.PathUtils;
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
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.Optional;

import static com.intel.bkp.fpgacerts.cbor.LocatorType.CER;
import static com.intel.bkp.fpgacerts.cbor.LocatorType.CORIM;
import static com.intel.bkp.fpgacerts.cbor.LocatorType.XCORIM;
import static com.intel.bkp.test.RandomUtils.generateRandomBytes;
import static com.intel.bkp.test.RandomUtils.generateRandomHex;
import static com.intel.bkp.test.rim.ComidBuilderUtils.environmentMap;
import static com.intel.bkp.test.rim.ComidBuilderUtils.measurementMap;
import static com.intel.bkp.test.rim.ComidBuilderUtils.versionMap;
import static com.intel.bkp.utils.HexConverter.fromHex;
import static com.intel.bkp.utils.HexConverter.toHex;

@NoArgsConstructor(access = AccessLevel.PRIVATE)
@Setter
@Getter
@Accessors(fluent = true)
public class RimGenerator {

    public static final String DP_URL = "http://localhost:9090/content/IPCS";
    public static final int ISSUER_KEY_LEN = 20;
    public static final int MANIFEST_ID_LEN = 16;
    private static final String PROFILE = "6086480186F84D010F06";
    private static final CborSignatureVerifier CBOR_SIGNATURE_VERIFIER = new CborSignatureVerifier();

    private String distributionPointUrl = DP_URL;
    private Family family = Family.AGILEX;
    private String layer1Digest = toHex(generateRandomBytes(48));
    private boolean signed = true;
    private boolean design = false;
    private boolean expired = false;
    private PrivateKey privateKey;
    private PublicKey publicKey;
    private String manifestId = "51ac25b8dc58405cb4c94772120ba68a";
    private Comid fwComid;
    private Comid designComid;
    private List<LocatorItem> locators = new ArrayList<>();

    public static RimGenerator instance() {
        return new RimGenerator();
    }

    public RimGenerator keyPair(KeyPair keyPair) {
        this.privateKey = keyPair.getPrivate();
        this.publicKey = keyPair.getPublic();
        return this;
    }

    public byte[] generate() {
        if (signed) {
            return generateSigned();
        } else {
            return generateStandaloneUnsigned();
        }
    }

    public RimUnsigned generateUnsignedEntity() {
        final Comid comid;

        if (signed) {
            final String ski = SkiHelper.getSkiInBase64UrlForUrl(CurvePoint.from(publicKey).getAlignedDataToSize());
            locators.add(new LocatorItem(CER, prepareURL(CER, ski)));
            locators.add(new LocatorItem(XCORIM, prepareURL(XCORIM, ski)));
        }

        if (design) {
            final String fwId = SkiHelper.getFwIdInBase64UrlForUrl(fromHex(layer1Digest()));
            locators.add(new LocatorItem(CORIM, prepareURL(CORIM, fwId)));
        }

        if (design) {
            comid = Optional.ofNullable(designComid).orElseGet(this::prepareDesignRimComid);
        } else {
            comid = Optional.ofNullable(fwComid).orElseGet(this::prepareFirmwareComid);
        }

        return RimUnsigned.builder()
            .manifestId(manifestId)
            .comIds(List.of(comid))
            .locators(locators)
            .profile(List.of(PROFILE))
            .build();
    }

    @SneakyThrows
    private byte[] generateSigned() {
        final CborKeyPair signingKey = CborKeyPair.fromKeyPair(publicKey, privateKey);

        final byte[] payload = prepareUnsignedRim();
        final RimProtectedHeader protectedHeader = prepareProtectedHeader(AlgorithmId.ECDSA_384);
        final byte[] signed = CoseMessage1Signer.instance().sign(signingKey, payload, protectedHeader);

        final boolean verified = CBOR_SIGNATURE_VERIFIER.verify(signingKey.getPublicKey(), signed);
        assert verified : "Cbor signature verification failed after signing structure";

        return signed;
    }

    private RimProtectedHeader prepareProtectedHeader(AlgorithmId algorithmId) {
        final Instant now = Instant.now();
        return RimProtectedHeader.builder()
            .algorithmId(algorithmId)
            .contentType(ProtectedHeaderType.RIM.getContentType())
            .issuerKeyId(generateRandomHex(ISSUER_KEY_LEN))
            .metaMap(ProtectedMetaMap.builder()
                .metaItems(
                    List.of(ProtectedSignersItem.builder()
                            .entityName("Firmware Author")
                            .build(),
                        ProtectedSignersItem.builder()
                            .entityName("CN=Intel:%s:ManSign".formatted(family.getFamilyName()))
                            .build())
                )
                .signatureValidity(expired ? now.minus(5, ChronoUnit.MINUTES) : now.plus(1, ChronoUnit.DAYS))
                .build())
            .build();
    }

    private byte[] generateStandaloneUnsigned() {
        final var rimUnsignedGeneric = generateUnsignedEntity();
        return RimUnsignedBuilder.instance()
            .standalone()
            .build(rimUnsignedGeneric);
    }

    private byte[] prepareUnsignedRim() {
        final var rimUnsignedGeneric = generateUnsignedEntity();
        return RimUnsignedBuilder.instance().build(rimUnsignedGeneric);
    }

    private String prepareURL(LocatorType locatorType, String uniquePart) {
        final String folder = switch (locatorType) {
            case CER -> "certs";
            case XCORIM -> "crls";
            case CORIM -> "rims";
            case NONE -> "";
        };
        return PathUtils.buildPath(distributionPointUrl, folder, prepareFileName(locatorType, uniquePart));
    }

    private String prepareFileName(LocatorType locatorType, String uniquePart) {
        final String familyName = family.getFamilyName().toLowerCase(Locale.ROOT);
        final String extension = locatorType.name().toLowerCase(Locale.ROOT);
        if (List.of(XCORIM, CER).contains(locatorType)) {
            return "RIM_Signing_%s_%s.%s".formatted(familyName, uniquePart, extension);
        } else if (CORIM == locatorType) {
            return "%s_L1_%s.%s".formatted(familyName, uniquePart, extension);
        } else {
            return "";
        }
    }

    private Comid prepareFirmwareComid() {
        final String layer0Digest = toHex(generateRandomBytes(64));

        return Comid.builder()
            .id(ComidId.builder().value("51F505F82911480B9F44B8A614FF2B18").build())
            .entities(List.of(ComidEntity.builder()
                .entityName("Firmware manifest")
                .roles(List.of(0))
                .build()))
            .claims(Claims.builder()
                .referenceTriples(List.of(
                    ReferenceTriple.builder()
                        .environmentMap(environmentMap(family.getFamilyName(), 0, 0))
                        .measurementMap(measurementMap(7, layer0Digest))
                        .build(),
                    ReferenceTriple.builder()
                        .environmentMap(environmentMap(family.getFamilyName(), 1, 0))
                        .measurementMap(measurementMap(7, layer1Digest)).build()))
                .endorsedTriples(List.of(ReferenceTriple.builder()
                    .environmentMap(environmentMap("6086480186F84D010F048148", 1))
                    .measurementMap(versionMap("release-2023.28.1.1", "3"))
                    .build()))
                .build())
            .build();
    }

    private Comid prepareDesignRimComid() {

        final String digest0 = toHex(generateRandomBytes(48));
        final String digest1 = toHex(generateRandomBytes(48));
        final String digest2 = toHex(generateRandomBytes(48));

        final List<ReferenceTriple> referenceTriples = List.of(
            ReferenceTriple.builder()
                .environmentMap(environmentMap("6086480186F84D010F0401", 2))
                .measurementMap(measurementMap("0000000003000000", "FFFFFFFF000000FF"))
                .build(),
            ReferenceTriple.builder()
                .environmentMap(environmentMap("6086480186F84D010F0402", 2))
                .measurementMap(measurementMap(7, digest0)).build(),
            ReferenceTriple.builder()
                .environmentMap(environmentMap("6086480186F84D010F0403", 2))
                .measurementMap(measurementMap(7, digest1)).build(),
            ReferenceTriple.builder()
                .environmentMap(environmentMap("6086480186F84D010F0405", 2))
                .measurementMap(measurementMap(7, digest2)).build(),
            ReferenceTriple.builder()
                .environmentMap(environmentMap("6086480186F84D010F048148", 1))
                .measurementMap(versionMap("release-2021.3.4.2", "3"))
                .build()
        );

        return Comid.builder()
            .id(ComidId.builder().value("5CC21C1EDC37453D8FF559AFB335371C").build())
            .entities(List.of(
                ComidEntity.builder()
                    .entityName("Design Author")
                    .regId("")
                    .roles(List.of(0))
                    .build()
            ))
            .claims(Claims.builder()
                .referenceTriples(referenceTriples)
                .endorsedTriples(List.of(ReferenceTriple.builder()
                    .environmentMap(environmentMap("6086480186F84D010F048149", null))
                    .measurementMap(versionMap("", null))
                    .build()))
                .build())
            .build();
    }
}

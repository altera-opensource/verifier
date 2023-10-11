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

package com.intel.bkp.fpgacerts.cbor.rim.builder;

import com.intel.bkp.fpgacerts.cbor.RimBuilderBase;
import com.intel.bkp.fpgacerts.cbor.rim.Comid;
import com.intel.bkp.fpgacerts.cbor.rim.comid.ComidEntity;
import com.intel.bkp.fpgacerts.cbor.rim.comid.Digest;
import com.intel.bkp.fpgacerts.cbor.rim.comid.EnvironmentMap;
import com.intel.bkp.fpgacerts.cbor.rim.comid.MeasurementVersion;
import com.intel.bkp.fpgacerts.cbor.rim.comid.ReferenceTriple;
import com.upokecenter.cbor.CBORObject;
import lombok.AccessLevel;
import lombok.NoArgsConstructor;

import java.util.List;
import java.util.Optional;
import java.util.regex.Pattern;

import static com.intel.bkp.fpgacerts.cbor.CborTagsConstant.CBOR_LOCATOR_ITEM_TAG;
import static com.intel.bkp.fpgacerts.cbor.rim.comid.Claims.CBOR_ENDORSED_TRIPLES_KEY;
import static com.intel.bkp.fpgacerts.cbor.rim.comid.Claims.CBOR_REFERENCE_TRIPLES_KEY;
import static com.intel.bkp.fpgacerts.cbor.rim.comid.ComidEntity.CBOR_ENTITY_NAME_KEY;
import static com.intel.bkp.fpgacerts.cbor.rim.comid.ComidEntity.CBOR_REG_ID_KEY;
import static com.intel.bkp.fpgacerts.cbor.rim.comid.ComidEntity.CBOR_ROLES_KEY;
import static com.intel.bkp.fpgacerts.cbor.rim.comid.MeasurementMap.CBOR_DIGESTS_KEY;
import static com.intel.bkp.fpgacerts.cbor.rim.comid.MeasurementMap.CBOR_MEAS_VERSION_KEY;
import static com.intel.bkp.fpgacerts.cbor.rim.comid.MeasurementMap.CBOR_RAW_VALUE_KEY;
import static com.intel.bkp.fpgacerts.cbor.rim.comid.MeasurementMap.CBOR_RAW_VALUE_MASK_KEY;
import static com.intel.bkp.fpgacerts.cbor.rim.comid.MeasurementMap.CBOR_SVN_KEY;
import static com.intel.bkp.fpgacerts.cbor.rim.comid.MeasurementMap.CBOR_TAGGED_RAW_VALUE_TYPE;
import static com.intel.bkp.fpgacerts.cbor.rim.comid.MeasurementMap.CBOR_TAGGED_SVN_LOWER;
import static com.intel.bkp.fpgacerts.cbor.rim.comid.MeasurementVersion.CBOR_VERSION_KEY;
import static com.intel.bkp.fpgacerts.cbor.rim.comid.MeasurementVersion.CBOR_VERSION_SCHEME_KEY;
import static com.intel.bkp.fpgacerts.cbor.rim.comid.ReferenceTriple.CBOR_ENVIRONMENTS_KEY;
import static com.intel.bkp.fpgacerts.cbor.rim.comid.ReferenceTriple.CBOR_MEASUREMENTS_KEY;
import static com.intel.bkp.utils.HexConverter.fromHex;
import static java.util.Optional.ofNullable;

@NoArgsConstructor(access = AccessLevel.PRIVATE)
public class RimCoMIDBuilder extends RimBuilderBase<Comid> {

    private static final Pattern POSSITIVE_INTEGER_PATTERN = Pattern.compile("^[0-9]+$");

    public static RimCoMIDBuilder instance() {
        return new RimCoMIDBuilder();
    }

    @Override
    public byte[] build(Comid data) {
        return CBORObject.NewOrderedMap()
            .Add(Comid.CBOR_ID_KEY, buildIdNode(data))
            .Add(Comid.CBOR_ENTITIES_KEY, buildEntitiesNode(data.getEntities().get(0)))
            .Add(Comid.CBOR_CLAIMS_KEY, buildClaimsNode(data))
            .EncodeToBytes();
    }

    public RimCoMIDBuilder designRim(boolean designRim) {
        setDesign(designRim);
        return this;
    }

    private static CBORObject buildIdNode(Comid data) {
        return CBORObject.NewMap()
            .Add(0, CBORObject.FromObject(fromHex(data.getId().getValue())));
    }

    private CBORObject buildEntitiesNode(ComidEntity comidEntity) {
        final CBORObject cborMap = CBORObject.NewMap();
        cborMap.Add(CBOR_ENTITY_NAME_KEY, CBORObject.FromObject(comidEntity.getEntityName()));

        if (isDesign()) {
            Optional.ofNullable(comidEntity.getRegId()).ifPresent(
                item -> cborMap.Add(CBOR_REG_ID_KEY, CBORObject.FromObjectAndTag(item, CBOR_LOCATOR_ITEM_TAG))
            );
        }
        cborMap.Add(CBOR_ROLES_KEY, CBORObject.FromObject(comidEntity.getRoles()));

        return CBORObject.NewArray().Add(cborMap);
    }

    private static CBORObject buildClaimsNode(Comid data) {
        return CBORObject.NewMap()
            .Add(CBOR_REFERENCE_TRIPLES_KEY, buildReferenceTriplesArray(data))
            .Add(CBOR_ENDORSED_TRIPLES_KEY, buildEndorsedTriplesArray(data));
    }

    private static CBORObject buildReferenceTriplesArray(Comid data) {
        final var mainArray = CBORObject.NewArray();

        data.getClaims().getReferenceTriples()
            .forEach(triple -> mainArray.Add(CBORObject.NewArray().Add(CBORObject.NewOrderedMap()
                    .Add(CBOR_ENVIRONMENTS_KEY, buildEnvironmentNodeMap(triple)))
                .Add(CBORObject.NewArray().Add(CBORObject.NewMap()
                    .Add(CBOR_MEASUREMENTS_KEY, buildMeasurementNodeMap(triple))
                ))));

        return mainArray;
    }

    private static CBORObject buildMeasurementNodeMap(ReferenceTriple triple) {
        final var measurementMap = triple.getMeasurementMap();
        final CBORObject cborMap = CBORObject.NewMap();

        ofNullable(measurementMap.getVersion())
            .map(RimCoMIDBuilder::buildVersionNode)
            .ifPresent(item -> cborMap.Add(CBOR_MEAS_VERSION_KEY, item));

        ofNullable(measurementMap.getSvn())
            .map(RimCoMIDBuilder::buildSvnNode)
            .ifPresent(item -> cborMap.Add(CBOR_SVN_KEY, item));

        ofNullable(measurementMap.getDigests())
            .map(RimCoMIDBuilder::buildDigestNodeArray)
            .ifPresent(item -> cborMap.Add(CBOR_DIGESTS_KEY, CBORObject.NewArray().Add(item)));

        ofNullable(measurementMap.getRawValue())
            .ifPresent(item -> cborMap.Add(CBOR_RAW_VALUE_KEY,
                CBORObject.FromObjectAndTag(fromHex(item), CBOR_TAGGED_RAW_VALUE_TYPE)));

        ofNullable(measurementMap.getRawValueMask())
            .ifPresent(item -> cborMap.Add(CBOR_RAW_VALUE_MASK_KEY, CBORObject.FromObject(fromHex(item))));

        return cborMap;
    }

    private static CBORObject buildVersionNode(MeasurementVersion versionObj) {
        return CBORObject.NewMap()
            .Add(CBOR_VERSION_KEY, CBORObject.FromObject(versionObj.getVersion()))
            .Add(CBOR_VERSION_SCHEME_KEY, buildVersionScheme(versionObj.getVersionScheme()));
    }

    private static CBORObject buildVersionScheme(String versionScheme) {
        if (isNumeric(versionScheme)) {
            return CBORObject.FromObject(Integer.valueOf(versionScheme));
        } else {
            return CBORObject.FromObject(versionScheme);
        }
    }

    private static CBORObject buildSvnNode(int svn) {
        return CBORObject.FromObjectAndTag(svn, CBOR_TAGGED_SVN_LOWER);
    }

    private static CBORObject buildEndorsedTriplesArray(Comid data) {
        final var mainArray = CBORObject.NewArray();

        data.getClaims().getEndorsedTriples()
            .forEach(triple -> mainArray
                .Add(CBORObject.NewArray().Add(CBORObject.NewOrderedMap().Add(CBOR_ENVIRONMENTS_KEY,
                        buildEnvironmentNodeMap(triple)))
                    .Add(CBORObject.NewArray().Add(CBORObject.NewOrderedMap().Add(CBOR_MEASUREMENTS_KEY,
                        CBORObject.NewOrderedMap().Add(0, buildEndorsedMeasurementNodeMap(triple)))))));

        return mainArray;
    }

    private static CBORObject buildEndorsedMeasurementNodeMap(ReferenceTriple data) {
        final var version = data.getMeasurementMap().getVersion();

        final CBORObject cborMap = CBORObject.NewMap();

        ofNullable(version.getVersion())
            .ifPresent(item -> cborMap.Add(CBOR_VERSION_KEY, item));

        ofNullable(version.getVersionScheme())
            .map(RimCoMIDBuilder::buildVersionScheme)
            .ifPresent(item -> cborMap.Add(CBOR_VERSION_SCHEME_KEY, item));

        return cborMap;
    }

    private static CBORObject buildDigestNodeArray(List<Digest> data) {
        final var digest = data.get(0);

        return CBORObject.NewArray()
            .Add(CBORObject.FromObject(digest.getAlgorithm()))
            .Add(CBORObject.FromObject(fromHex(digest.getValue())));
    }

    private static CBORObject buildEnvironmentNodeMap(ReferenceTriple data) {
        final var environmentMap = data.getEnvironmentMap();
        final var mapObject = CBORObject.NewMap();

        ofNullable(environmentMap.getClassId())
            .map(val -> CBORObject.FromObjectAndTag(fromHex(val), EnvironmentMap.CBOR_CLASS_ID_TAG))
            .ifPresent(val -> mapObject.Add(EnvironmentMap.CBOR_CLASS_ID_KEY, val));
        ofNullable(environmentMap.getVendor())
            .ifPresent(val -> mapObject.Add(EnvironmentMap.CBOR_VENDOR_KEY, val));
        ofNullable(environmentMap.getModel())
            .ifPresent(val -> mapObject.Add(EnvironmentMap.CBOR_MODEL_KEY, val));
        ofNullable(environmentMap.getLayer())
            .ifPresent(val -> mapObject.Add(EnvironmentMap.CBOR_LAYER_KEY, val));
        ofNullable(environmentMap.getIndex())
            .ifPresent(val -> mapObject.Add(EnvironmentMap.CBOR_INDEX_KEY, val));

        return mapObject;
    }

    private static boolean isNumeric(String data) {
        if (data == null) {
            return false;
        }
        return POSSITIVE_INTEGER_PATTERN.matcher(data).matches();
    }
}

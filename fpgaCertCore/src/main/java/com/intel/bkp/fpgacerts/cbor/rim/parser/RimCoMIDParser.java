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

package com.intel.bkp.fpgacerts.cbor.rim.parser;

import com.intel.bkp.fpgacerts.cbor.CborParserBase;
import com.intel.bkp.fpgacerts.cbor.rim.Comid;
import com.intel.bkp.fpgacerts.cbor.rim.comid.Claims;
import com.intel.bkp.fpgacerts.cbor.rim.comid.ComidEntity;
import com.intel.bkp.fpgacerts.cbor.rim.comid.ComidId;
import com.intel.bkp.fpgacerts.cbor.rim.comid.Digest;
import com.intel.bkp.fpgacerts.cbor.rim.comid.EnvironmentMap;
import com.intel.bkp.fpgacerts.cbor.rim.comid.MeasurementMap;
import com.intel.bkp.fpgacerts.cbor.rim.comid.MeasurementVersion;
import com.intel.bkp.fpgacerts.cbor.rim.comid.ReferenceTriple;
import com.intel.bkp.utils.HexConverter;
import com.upokecenter.cbor.CBORObject;
import com.upokecenter.cbor.CBORType;
import lombok.AccessLevel;
import lombok.NoArgsConstructor;

import java.util.ArrayList;
import java.util.List;
import java.util.Optional;

import static com.intel.bkp.fpgacerts.cbor.rim.comid.Claims.CBOR_ENDORSED_TRIPLES_KEY;
import static com.intel.bkp.fpgacerts.cbor.rim.comid.Claims.CBOR_REFERENCE_TRIPLES_KEY;
import static com.intel.bkp.fpgacerts.cbor.rim.comid.Digest.CBOR_DIGEST_ALG_KEY;
import static com.intel.bkp.fpgacerts.cbor.rim.comid.Digest.CBOR_DIGEST_VAL_KEY;
import static com.intel.bkp.fpgacerts.cbor.rim.comid.MeasurementMap.CBOR_DIGESTS_KEY;
import static com.intel.bkp.fpgacerts.cbor.rim.comid.MeasurementMap.CBOR_MEAS_VERSION_KEY;
import static com.intel.bkp.fpgacerts.cbor.rim.comid.MeasurementMap.CBOR_RAW_VALUE_KEY;
import static com.intel.bkp.fpgacerts.cbor.rim.comid.MeasurementMap.CBOR_RAW_VALUE_MASK_KEY;
import static com.intel.bkp.fpgacerts.cbor.rim.comid.MeasurementMap.CBOR_SVN_KEY;
import static com.intel.bkp.fpgacerts.cbor.rim.comid.MeasurementMap.CBOR_TAGGED_SVN_LOWER;
import static com.intel.bkp.fpgacerts.cbor.rim.comid.MeasurementVersion.CBOR_VERSION_KEY;
import static com.intel.bkp.fpgacerts.cbor.rim.comid.MeasurementVersion.CBOR_VERSION_SCHEME_KEY;
import static com.intel.bkp.fpgacerts.cbor.rim.comid.ReferenceTriple.CBOR_ENVIRONMENTS_KEY;
import static com.intel.bkp.fpgacerts.cbor.rim.comid.ReferenceTriple.CBOR_MEASUREMENTS_KEY;
import static java.util.Optional.ofNullable;

@NoArgsConstructor(access = AccessLevel.PRIVATE)
public class RimCoMIDParser extends CborParserBase<Comid> {

    public static RimCoMIDParser instance() {
        return new RimCoMIDParser();
    }

    @Override
    public Comid parse(CBORObject cbor) {
        final var comidId = parseComidId(cbor);
        final var comidEntity = parseComidEntity(cbor);
        final Claims claims = parseClaims(cbor);

        return Comid.builder()
            .id(comidId)
            .entities(List.of(comidEntity))
            .claims(claims)
            .build();
    }

    private static ComidId parseComidId(CBORObject cbor) {
        final var id = HexConverter.toHex(cbor.get(Comid.CBOR_ID_KEY).get(0).GetByteString());
        return ComidId.builder().value(id).build();
    }

    private static ComidEntity parseComidEntity(CBORObject cbor) {
        final CBORObject cborObject = cbor.get(Comid.CBOR_ENTITIES_KEY).get(0);
        final var entityName = cborObject.get(0).AsString();

        final var regId = ofNullable(cborObject.get(1))
            .map(CBORObject::AsString)
            .orElse(null);

        final List<Integer> roles = new ArrayList<>();
        for (int inc = 0; inc < cborObject.get(2).size(); inc++) {
            roles.add(cborObject.get(2).get(inc).AsInt32());
        }
        return ComidEntity.builder()
            .entityName(entityName)
            .roles(roles)
            .regId(regId)
            .build();
    }

    private static Claims parseClaims(CBORObject cbor) {
        final var claims = cbor.get(Comid.CBOR_CLAIMS_KEY);
        return Claims.builder()
            .referenceTriples(parseTriples(claims.get(CBOR_REFERENCE_TRIPLES_KEY)))
            .endorsedTriples(parseTriples(claims.get(CBOR_ENDORSED_TRIPLES_KEY)))
            .build();
    }

    private static List<ReferenceTriple> parseTriples(CBORObject cborTriplesData) {
        return Optional.ofNullable(cborTriplesData)
            .map(CBORObject::getValues)
            .orElse(List.of())
            .stream()
            .map(triple -> ReferenceTriple.builder()
                .environmentMap(parseEnvironmentMap(triple.get(CBOR_ENVIRONMENTS_KEY).get(0)))
                .measurementMap(parseMeasurementMap(triple.get(CBOR_MEASUREMENTS_KEY).get(0)))
                .build())
            .toList();
    }

    private static MeasurementMap parseMeasurementMap(CBORObject arrItem) {
        final CBORObject cborObject = arrItem.get(1);

        final var builder = MeasurementMap.builder();

        ofNullable(cborObject.get(CBOR_SVN_KEY))
            .map(RimCoMIDParser::parseSvnField)
            .ifPresent(builder::svn);

        ofNullable(cborObject.get(CBOR_DIGESTS_KEY))
            .map(RimCoMIDParser::parseDigest)
            .ifPresent(builder::digests);

        ofNullable(cborObject.get(CBOR_RAW_VALUE_KEY))
            .map(CBORObject::GetByteString)
            .map(HexConverter::toHex)
            .ifPresent(builder::rawValue);

        ofNullable(cborObject.get(CBOR_RAW_VALUE_MASK_KEY))
            .map(CBORObject::GetByteString)
            .map(HexConverter::toHex)
            .ifPresent(builder::rawValueMask);

        ofNullable(cborObject.get(CBOR_MEAS_VERSION_KEY))
            .map(RimCoMIDParser::getMeasurementVersion)
            .ifPresent(builder::version);

        return builder.build();
    }

    private static List<Digest> parseDigest(CBORObject cborObject) {
        final CBORObject digestsObj = cborObject.get(0);
        final Digest digest = Digest.builder()
            .algorithm(digestsObj.get(CBOR_DIGEST_ALG_KEY).AsInt32())
            .value(HexConverter.toHex(digestsObj.get(CBOR_DIGEST_VAL_KEY).GetByteString()))
            .build();
        return List.of(digest);
    }

    private static Integer parseSvnField(CBORObject svnObject) {
        if (svnObject.getTagCount() > 0 && svnObject.getMostInnerTag().compareTo(CBOR_TAGGED_SVN_LOWER) >= 0) {
            return svnObject.AsEIntegerValue().ToInt32Checked();
        } else {
            return null;
        }
    }

    private static MeasurementVersion getMeasurementVersion(CBORObject obj) {
        final var builder = MeasurementVersion.builder();

        ofNullable(obj.get(CBOR_VERSION_SCHEME_KEY))
            .map(item -> {
                if (item.getType() != CBORType.TextString) {
                    return String.valueOf(item.AsInt32());
                } else {
                    return item.AsString();
                }
            })
            .ifPresent(builder::versionScheme);

        ofNullable(obj.get(CBOR_VERSION_KEY))
            .map(CBORObject::AsString)
            .ifPresent(builder::version);

        return builder.build();
    }

    private static EnvironmentMap parseEnvironmentMap(CBORObject item) {
        final var builder = EnvironmentMap.builder();

        ofNullable(item.get(EnvironmentMap.CBOR_CLASS_ID_KEY))
            .map(CBORObject::GetByteString)
            .map(HexConverter::toHex)
            .ifPresent(builder::classId);

        ofNullable(item.get(EnvironmentMap.CBOR_VENDOR_KEY))
            .map(CBORObject::AsString)
            .ifPresent(builder::vendor);

        ofNullable(item.get(EnvironmentMap.CBOR_MODEL_KEY))
            .map(CBORObject::AsString)
            .ifPresent(builder::model);

        ofNullable(item.get(EnvironmentMap.CBOR_LAYER_KEY))
            .map(CBORObject::AsInt32)
            .ifPresent(builder::layer);

        ofNullable(item.get(EnvironmentMap.CBOR_INDEX_KEY))
            .map(CBORObject::AsInt32)
            .ifPresent(builder::index);

        return builder.build();
    }
}

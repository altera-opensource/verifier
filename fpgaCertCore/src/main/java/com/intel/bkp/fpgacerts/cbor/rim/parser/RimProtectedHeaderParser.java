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

import com.intel.bkp.fpgacerts.cbor.CborObjectParser;
import com.intel.bkp.fpgacerts.cbor.CborParserBase;
import com.intel.bkp.fpgacerts.cbor.CborTagsConstant;
import com.intel.bkp.fpgacerts.cbor.ProtectedHeader;
import com.intel.bkp.fpgacerts.cbor.ProtectedHeaderType;
import com.intel.bkp.fpgacerts.cbor.exception.CborParserException;
import com.intel.bkp.fpgacerts.cbor.rim.ProtectedMetaMap;
import com.intel.bkp.fpgacerts.cbor.rim.ProtectedSignersItem;
import com.intel.bkp.fpgacerts.cbor.rim.RimProtectedHeader;
import com.intel.bkp.fpgacerts.cbor.signer.cose.exception.CoseException;
import com.intel.bkp.fpgacerts.cbor.signer.cose.model.AlgorithmId;
import com.intel.bkp.fpgacerts.cbor.utils.CborDateConverter;
import com.intel.bkp.utils.HexConverter;
import com.upokecenter.cbor.CBORObject;
import com.upokecenter.cbor.CBORType;
import lombok.AccessLevel;
import lombok.NoArgsConstructor;

import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;

import static java.util.Optional.ofNullable;

@NoArgsConstructor(access = AccessLevel.PRIVATE)
public class RimProtectedHeaderParser extends CborParserBase<RimProtectedHeader> {

    public static RimProtectedHeaderParser instance() {
        return new RimProtectedHeaderParser();
    }

    @Override
    public RimProtectedHeader parse(CBORObject cbor) {
        final var algorithmId = cbor.get(ProtectedHeader.CBOR_PROT_ALG_ID_KEY);
        final var contentType = cbor.get(ProtectedHeader.CBOR_PROT_CONTENT_TYPE_KEY).AsString();
        final var issuerKeyId =
            HexConverter.toHex(cbor.get(ProtectedHeader.CBOR_PROT_ISSUER_KEY_ID_KEY).GetByteString());
        final var metaMap = parseMetaMap(cbor);

        try {
            return RimProtectedHeader.builder()
                .algorithmId(AlgorithmId.fromCbor(algorithmId))
                .contentType(contentType)
                .issuerKeyId(issuerKeyId)
                .metaMap(metaMap)
                .build();
        } catch (CoseException e) {
            throw new CborParserException("Failed to parse rimProtected", e);
        }
    }

    private static ProtectedMetaMap parseMetaMap(CBORObject cbor) {
        CBORObject metaMapCbor = Optional.ofNullable(cbor.get(ProtectedHeaderType.RIM.getCborTag()))
            .orElseGet(() -> cbor.get(ProtectedHeaderType.XRIM.getCborTag()));

        if (CBORType.ByteString == metaMapCbor.getType()) {
            metaMapCbor = CborObjectParser.instance().parse(metaMapCbor.GetByteString());
        }

        final var signerDetails = metaMapCbor.get(CborTagsConstant.CBOR_PROT_META_MAP_SIGNER_KEY);

        final List<ProtectedSignersItem> metaMapItems = new ArrayList<>();
        for (int inc = 0; inc < signerDetails.size(); inc++) {
            final var currentItem = signerDetails.get(inc);
            final String entityName = parseEntityName(currentItem);
            metaMapItems.add(ProtectedSignersItem.builder()
                .entityName(entityName)
                .build());
        }

        final var builder = ProtectedMetaMap.builder()
            .metaItems(metaMapItems);

        parseSignatureValidity(metaMapCbor.get(CborTagsConstant.CBOR_PROT_META_MAP_SIGNATURE_VALIDITY))
            .ifPresent(builder::signatureValidity);

        return builder.build();
    }

    private static String parseEntityName(CBORObject currentItem) {
        final String entityName;
        if (isXrimProtected(currentItem)) {
            entityName = currentItem.AsString();
        } else {
            entityName = currentItem.get(ProtectedSignersItem.CBOR_PROT_META_ENTITY_NAME_KEY).AsString();
        }
        return entityName;
    }

    private static Optional<Instant> parseSignatureValidity(CBORObject cbor) {
        return ofNullable(cbor)
            .map(item -> {
                if (isXrimProtected(item)) {
                    return item;
                } else {
                    return cbor.get(CborTagsConstant.CBOR_PROT_META_MAP_NOT_AFTER);
                }
            })
            .map(CBORObject::AsString)
            .map(CborDateConverter::fromString);

    }

    private static boolean isXrimProtected(CBORObject currentItem) {
        return CBORType.TextString == currentItem.getType();
    }
}

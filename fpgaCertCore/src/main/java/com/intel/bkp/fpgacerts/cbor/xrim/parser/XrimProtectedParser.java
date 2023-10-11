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

package com.intel.bkp.fpgacerts.cbor.xrim.parser;

import com.intel.bkp.fpgacerts.cbor.ProtectedHeaderType;
import com.intel.bkp.fpgacerts.cbor.exception.CborParserException;
import com.intel.bkp.fpgacerts.cbor.rim.ProtectedSignersItem;
import com.intel.bkp.fpgacerts.cbor.CborObjectParser;
import com.intel.bkp.fpgacerts.cbor.CborParserBase;
import com.intel.bkp.fpgacerts.cbor.signer.cose.exception.CoseException;
import com.intel.bkp.fpgacerts.cbor.signer.cose.model.AlgorithmId;
import com.intel.bkp.fpgacerts.cbor.utils.CborDateConverter;
import com.intel.bkp.fpgacerts.cbor.xrim.XrimProtectedHeader;
import com.intel.bkp.fpgacerts.cbor.xrim.XrimProtectedMetaMap;
import com.intel.bkp.utils.HexConverter;
import com.upokecenter.cbor.CBORObject;
import com.upokecenter.cbor.CBORType;
import lombok.AccessLevel;
import lombok.NoArgsConstructor;

import java.time.Instant;
import java.util.Optional;

import static com.intel.bkp.fpgacerts.cbor.CborTagsConstant.CBOR_PROT_META_MAP_NOT_AFTER;
import static com.intel.bkp.fpgacerts.cbor.CborTagsConstant.CBOR_PROT_META_MAP_SIGNATURE_VALIDITY;
import static com.intel.bkp.fpgacerts.cbor.CborTagsConstant.CBOR_PROT_META_MAP_SIGNER_KEY;
import static com.intel.bkp.fpgacerts.cbor.ProtectedHeader.CBOR_PROT_ALG_ID_KEY;
import static com.intel.bkp.fpgacerts.cbor.ProtectedHeader.CBOR_PROT_CONTENT_TYPE_KEY;
import static com.intel.bkp.fpgacerts.cbor.ProtectedHeader.CBOR_PROT_ISSUER_KEY_ID_KEY;
import static com.intel.bkp.fpgacerts.cbor.rim.ProtectedSignersItem.CBOR_PROT_META_ENTITY_NAME_KEY;
import static java.util.Optional.ofNullable;

@NoArgsConstructor(access = AccessLevel.PRIVATE)
public class XrimProtectedParser extends CborParserBase<XrimProtectedHeader> {

    public static XrimProtectedParser instance() {
        return new XrimProtectedParser();
    }

    @Override
    public XrimProtectedHeader parse(CBORObject cbor) {
        final var algorithmId = cbor.get(CBOR_PROT_ALG_ID_KEY);
        final var contentType = cbor.get(CBOR_PROT_CONTENT_TYPE_KEY).AsString();
        final var issuerKeyId = HexConverter.toHex(cbor.get(CBOR_PROT_ISSUER_KEY_ID_KEY).GetByteString());
        final var metaMap = parseMetaMap(cbor);

        try {
            return XrimProtectedHeader.builder()
                .algorithmId(AlgorithmId.fromCbor(algorithmId))
                .contentType(contentType)
                .issuerKeyId(issuerKeyId)
                .metaMap(metaMap)
                .build();
        } catch (CoseException e) {
            throw new CborParserException("Failed to parse rimProtected", e);
        }
    }

    private static XrimProtectedMetaMap parseMetaMap(CBORObject cbor) {
        CBORObject metaMapCbor = Optional.ofNullable(cbor.get(ProtectedHeaderType.RIM.getCborTag()))
            .orElseGet(() -> cbor.get(ProtectedHeaderType.XRIM.getCborTag()));

        if (CBORType.ByteString == metaMapCbor.getType()) {
            metaMapCbor = CborObjectParser.instance().parse(metaMapCbor.GetByteString());
        }

        final var signerDetails = metaMapCbor.get(CBOR_PROT_META_MAP_SIGNER_KEY);

        final var builder = XrimProtectedMetaMap.builder();

        for (int inc = 0; inc < signerDetails.size(); inc++) {
            final var currentItem = signerDetails.get(inc);
            final String entityName = parseEntityName(currentItem);
            builder.metaItem(ProtectedSignersItem.builder()
                .entityName(entityName)
                .build());
        }

        parseSignatureValidity(metaMapCbor.get(CBOR_PROT_META_MAP_SIGNATURE_VALIDITY))
            .ifPresent(builder::issuedDate);

        return builder.build();
    }

    private static String parseEntityName(CBORObject currentItem) {
        final String entityName;
        if (isXrimProtected(currentItem)) {
            entityName = currentItem.AsString();
        } else {
            entityName = currentItem.get(CBOR_PROT_META_ENTITY_NAME_KEY).AsString();
        }
        return entityName;
    }

    private static Optional<Instant> parseSignatureValidity(CBORObject cbor) {
        return ofNullable(cbor)
            .map(item -> {
                if (isXrimProtected(item)) {
                    return item;
                } else {
                    return cbor.get(CBOR_PROT_META_MAP_NOT_AFTER);
                }
            })
            .map(CBORObject::AsString)
            .map(CborDateConverter::fromString);

    }

    private static boolean isXrimProtected(CBORObject currentItem) {
        return CBORType.TextString == currentItem.getType();
    }
}

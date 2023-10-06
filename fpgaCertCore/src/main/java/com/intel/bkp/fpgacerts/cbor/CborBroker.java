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

package com.intel.bkp.fpgacerts.cbor;

import com.intel.bkp.fpgacerts.cbor.exception.CborParserException;
import com.upokecenter.cbor.CBORObject;
import lombok.AccessLevel;
import lombok.NoArgsConstructor;
import lombok.extern.slf4j.Slf4j;

import static com.intel.bkp.fpgacerts.cbor.CborTagsConstant.CBOR_RIM_MAIN_TAG;
import static com.intel.bkp.fpgacerts.cbor.CborTagsConstant.CBOR_RIM_SIGNED_TAG;
import static com.intel.bkp.fpgacerts.cbor.CborTagsConstant.CBOR_RIM_UNSIGNED_TAG;
import static com.intel.bkp.fpgacerts.cbor.CborTagsConstant.CBOR_XRIM_MAIN_TAG;
import static com.intel.bkp.fpgacerts.cbor.CborTagsConstant.CBOR_XRIM_SIGNED_TAG;
import static com.intel.bkp.fpgacerts.cbor.CborTagsConstant.CBOR_XRIM_UNSIGNED_TAG;

@Slf4j
@NoArgsConstructor(access = AccessLevel.PRIVATE)
public class CborBroker {

    public static CborConverter detectCborType(CBORObject rimCbor) {
        if (rimCbor.HasMostOuterTag(CBOR_RIM_MAIN_TAG)) {
            final CBORObject innerObject = rimCbor.UntagOne();
            if (innerObject.HasMostOuterTag(CBOR_RIM_SIGNED_TAG)) {
                log.info("Signed CoRIM detected");
                return CborConverter.RIM_SIGNED;
            } else if (innerObject.HasMostOuterTag(CBOR_RIM_UNSIGNED_TAG)) {
                log.info("Unsigned CoRIM detected");
                return CborConverter.RIM_UNSIGNED;
            } else {
                throw new CborParserException("CoRIM with incorrect outer signed/unsigned tag.");
            }
        } else if (rimCbor.HasMostOuterTag(CBOR_XRIM_MAIN_TAG)) {
            final CBORObject innerObject = rimCbor.UntagOne();
            if (innerObject.HasMostOuterTag(CBOR_XRIM_SIGNED_TAG)) {
                log.info("Signed XCoRIM detected");
                return CborConverter.XRIM_SIGNED;
            } else if (innerObject.HasMostOuterTag(CBOR_XRIM_UNSIGNED_TAG)) {
                log.info("Unsigned XCoRIM detected");
                return CborConverter.XRIM_UNSIGNED;
            } else {
                throw new CborParserException("XCoRIM with incorrect outer signed/unsigned tag.");
            }
        } else {
            throw new CborParserException("Unexpected CoRIM/XCoRIM outer tag.");
        }
    }
}

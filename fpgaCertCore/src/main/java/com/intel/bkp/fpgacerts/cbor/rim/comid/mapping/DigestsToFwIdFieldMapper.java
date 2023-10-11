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

package com.intel.bkp.fpgacerts.cbor.rim.comid.mapping;

import com.intel.bkp.fpgacerts.cbor.rim.comid.Digest;
import com.intel.bkp.fpgacerts.dice.tcbinfo.FwIdField;
import com.intel.bkp.fpgacerts.exceptions.FwidHashAlgNotSupported;
import lombok.AccessLevel;
import lombok.Getter;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.bouncycastle.asn1.nist.NISTObjectIdentifiers;

import java.util.Arrays;
import java.util.List;

@Slf4j
public class DigestsToFwIdFieldMapper {

    public FwIdField map(List<Digest> digests) {
        if (digests.isEmpty()) {
            return null;
        }

        // Assumption is that there is only 1 element in list.
        // The assumption may change in the future.
        if (digests.size() > 1) {
            log.warn("Multiple digests found - all except the first one will be ignored.");
        }

        final var digest = digests.get(0);
        return new FwIdField(
            HashAlgorithmRegistry.getOidById(digest.getAlgorithm()),
            digest.getValue()
        );
    }

    @Getter(value = AccessLevel.PACKAGE)
    @RequiredArgsConstructor
    enum HashAlgorithmRegistry {
        SHA256(1, NISTObjectIdentifiers.id_sha256.getId()),
        SHA384(7, NISTObjectIdentifiers.id_sha384.getId()),
        SHA512(8, NISTObjectIdentifiers.id_sha512.getId());

        private final int id;
        private final String oid;

        public static String getOidById(int id) {
            return Arrays.stream(values())
                .filter(alg -> alg.id == id)
                .map(alg -> alg.oid)
                .findFirst()
                .orElseThrow(() -> FwidHashAlgNotSupported.fromHashAlgId(id));
        }
    }
}

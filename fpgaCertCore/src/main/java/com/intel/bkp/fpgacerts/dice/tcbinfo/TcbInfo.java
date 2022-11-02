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

package com.intel.bkp.fpgacerts.dice.tcbinfo;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.bouncycastle.asn1.ASN1TaggedObject;

import java.util.EnumMap;
import java.util.Map;
import java.util.Optional;

@Slf4j
@RequiredArgsConstructor
public class TcbInfo {

    private final Map<TcbInfoField, Object> tcbInfoMap;

    public TcbInfo() {
        this(new EnumMap<>(TcbInfoField.class));
    }

    @SuppressWarnings("unchecked")
    public <T> Optional<T> get(TcbInfoField field) {
        return tcbInfoMap.containsKey(field)
               ? Optional.of((T) tcbInfoMap.get(field))
               : Optional.empty();
    }

    public void add(TcbInfoField tcbInfoField, ASN1TaggedObject object) {
        addInternal(tcbInfoField, tcbInfoField.getParser().parse(object));
    }

    public boolean isEmpty() {
        return tcbInfoMap.isEmpty();
    }

    private void addInternal(TcbInfoField tcbInfoFieldType, Object value) {
        if (!tcbInfoMap.containsKey(tcbInfoFieldType)) {
            tcbInfoMap.put(tcbInfoFieldType, value);
            return;
        }

        if (!tcbInfoMap.get(tcbInfoFieldType).equals(value)) {
            log.error("Object {} already exists but value mismatch.\nExisting: {}\nNew: {}",
                    tcbInfoFieldType.name(), tcbInfoMap.get(tcbInfoFieldType), value);
            throw new IllegalArgumentException("Object already exists but values mismatch.");
        }
    }
}

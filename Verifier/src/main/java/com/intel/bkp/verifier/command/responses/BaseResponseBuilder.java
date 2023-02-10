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

package com.intel.bkp.verifier.command.responses;

import com.intel.bkp.core.endianness.EndiannessActor;
import com.intel.bkp.utils.ByteSwap;
import com.intel.bkp.verifier.endianness.EndiannessStructureFields;
import com.intel.bkp.verifier.endianness.EndiannessStructureType;
import com.intel.bkp.verifier.interfaces.IEndiannessMap;
import lombok.Getter;
import lombok.Setter;

import java.util.EnumMap;

public abstract class BaseResponseBuilder<T> {

    @Setter
    protected EnumMap<EndiannessStructureType, IEndiannessMap> maps = new EnumMap<>(EndiannessStructureType.class);

    @Getter
    private EndiannessActor actor;

    public BaseResponseBuilder() {
        changeActor(EndiannessActor.SERVICE);
    }

    public abstract EndiannessStructureType currentStructureMap();

    public abstract T withActor(EndiannessActor actor);

    public abstract void initStructureMap(EndiannessStructureType currentStructureType, EndiannessActor currentActor);

    protected void changeActor(EndiannessActor actor) {
        if (getActor() != actor) {
            this.actor = actor;
            initStructureMap(currentStructureMap(), getActor());
        }
    }

    private IEndiannessMap getCurrentMap() {
        if (currentStructureMap() != null && maps.containsKey(currentStructureMap())) {
            return maps.get(currentStructureMap());
        } else {
            throw new IllegalStateException("Current structure map is absent or doesn't contain proper map");
        }
    }

    protected final byte[] convert(byte[] value, EndiannessStructureFields structureName) {
        return ByteSwap.getSwappedArrayByInt(value, getCurrentMap().get(structureName));
    }

    protected final short convertShort(short value, EndiannessStructureFields structureName) {
        return ByteSwap.getSwappedShort(value, getCurrentMap().get(structureName));
    }
}

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

import com.intel.bkp.core.endianess.EndianessActor;
import com.intel.bkp.utils.ByteSwap;
import com.intel.bkp.verifier.endianess.EndianessStructureFields;
import com.intel.bkp.verifier.endianess.EndianessStructureType;
import com.intel.bkp.verifier.interfaces.IEndianessMap;
import lombok.Getter;
import lombok.Setter;

import java.util.EnumMap;

public abstract class BaseResponseBuilder<T> {

    @Setter
    protected EnumMap<EndianessStructureType, IEndianessMap> maps = new EnumMap<>(EndianessStructureType.class);

    @Getter
    private EndianessActor actor;

    public BaseResponseBuilder() {
        changeActor(EndianessActor.SERVICE);
    }

    public abstract EndianessStructureType currentStructureMap();

    public abstract T withActor(EndianessActor actor);

    public abstract void initStructureMap(EndianessStructureType currentStructureType, EndianessActor currentActor);

    protected void changeActor(EndianessActor actor) {
        if (getActor() != actor) {
            this.actor = actor;
            initStructureMap(currentStructureMap(), getActor());
        }
    }

    private IEndianessMap getCurrentMap() {
        if (currentStructureMap() != null && maps.containsKey(currentStructureMap())) {
            return maps.get(currentStructureMap());
        } else {
            throw new IllegalStateException("Current structure map is absent or doesn't contain proper map");
        }
    }

    protected final byte[] convert(byte[] value, EndianessStructureFields structureName) {
        return ByteSwap.getSwappedArrayByInt(value, getCurrentMap().get(structureName));
    }

    protected final short convertShort(short value, EndianessStructureFields structureName) {
        return ByteSwap.getSwappedShort(value, getCurrentMap().get(structureName));
    }
}

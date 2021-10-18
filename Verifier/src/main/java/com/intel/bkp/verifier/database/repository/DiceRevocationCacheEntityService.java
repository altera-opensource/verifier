/*
 * This project is licensed as below.
 *
 * **************************************************************************
 *
 * Copyright 2020-2021 Intel Corporation. All Rights Reserved.
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

package com.intel.bkp.verifier.database.repository;

import com.intel.bkp.ext.utils.HexConverter;
import com.intel.bkp.verifier.database.model.DiceRevocationCacheEntity;
import com.intel.bkp.verifier.database.table.DiceTableDefinition;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.dbutils.handlers.BeanListHandler;

import java.sql.Connection;
import java.util.Optional;

@Slf4j
public class DiceRevocationCacheEntityService extends CacheEntityServiceBase {

    public DiceRevocationCacheEntityService(Connection connection) {
        super(connection, new DiceTableDefinition());
    }

    public DiceRevocationCacheEntityService store(DiceRevocationCacheEntity entity) {
        log.debug("Insert entity for deviceId: {}", entity.getDeviceId());
        insert(getParams(entity));
        return this;
    }

    public Optional<DiceRevocationCacheEntity> read(byte[] deviceId) {
        final String deviceIdHex = HexConverter.toHex(deviceId);
        log.debug("Reading cached entity for deviceId: {}", deviceIdHex);

        return select(getResultsHandler())
            .stream()
            .filter(entity -> entity.getDeviceId().equals(deviceIdHex))
            .findFirst();
    }

    private Object[] getParams(DiceRevocationCacheEntity entity) {
        return new Object[] {
            entity.getDeviceId(),
            entity.getRevoked()
        };
    }

    private BeanListHandler<DiceRevocationCacheEntity> getResultsHandler() {
        return new BeanListHandler<>(DiceRevocationCacheEntity.class);
    }
}

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

package com.intel.bkp.verifier.database.repository;

import com.intel.bkp.verifier.database.model.IMigratable;
import com.intel.bkp.verifier.database.model.ITableDefinition;
import com.intel.bkp.verifier.exceptions.DatabaseException;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.dbutils.QueryRunner;
import org.apache.commons.dbutils.ResultSetHandler;

import java.sql.Connection;
import java.sql.SQLException;
import java.util.Map;
import java.util.Optional;

import static com.intel.bkp.verifier.database.table.SQLiteChangelog.fromOrdinal;

@Slf4j
@RequiredArgsConstructor
public abstract class CacheEntityServiceBase implements IMigratable {

    protected final Connection connection;
    protected final ITableDefinition tableDefinition;
    protected final QueryRunner runner = new QueryRunner();

    @Override
    public void migrate(int oldVersion, int newVersion) {
        for (int currMigrationVersion = oldVersion; currMigrationVersion < newVersion; currMigrationVersion++) {
            updateSchema(currMigrationVersion);
        }
    }

    protected void updateSchema(int currentMigrationVersion) {
        final Map<Integer, String> migrationQuery = Optional.ofNullable(tableDefinition.getMigrationQuery())
            .orElse(Map.of());

        if (migrationQuery.containsKey(currentMigrationVersion)) {
            try {
                log.debug("Migrating table {} to version {}: {}", tableDefinition.getTableName(),
                    currentMigrationVersion + 1, fromOrdinal(currentMigrationVersion).getDescription());
                runner.update(connection, migrationQuery.get(currentMigrationVersion));
            } catch (SQLException e) {
                throw new DatabaseException("Failed to update database schema: " + tableDefinition.getTableName(), e);
            }
        }
    }

    protected <T> T select(ResultSetHandler<T> handler) {
        try {
            return runner.query(connection, tableDefinition.getSelectSQL(), handler);
        } catch (SQLException e) {
            throw new DatabaseException("Failed to select from: " + tableDefinition.getTableName(), e);
        }
    }

    protected void insert(Object[] params) {
        try {
            runner.update(connection, tableDefinition.getInsertSQL(), params);
        } catch (SQLException e) {
            throw new DatabaseException("Failed to create row in: " + tableDefinition.getTableName(), e);
        }
    }
}

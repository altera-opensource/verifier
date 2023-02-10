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

package com.intel.bkp.verifier.database;

import com.intel.bkp.verifier.database.repository.DiceRevocationCacheEntityService;
import com.intel.bkp.verifier.database.repository.S10CacheEntityService;
import com.intel.bkp.verifier.interfaces.IMigratable;
import com.intel.bkp.verifier.model.DatabaseConfiguration;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.dbutils.QueryRunner;
import org.apache.commons.dbutils.handlers.ScalarHandler;

import java.sql.Connection;
import java.sql.SQLException;
import java.util.Map;

import static com.intel.bkp.verifier.database.AttestationFlowType.DICE;
import static com.intel.bkp.verifier.database.AttestationFlowType.S10;

@Slf4j
public class SQLiteHelper implements AutoCloseable {

    /**
     * Updating database schema requires updating CURRENT_SCHEMA_VERSION.
     */
    private static final int CURRENT_SCHEMA_VERSION = 1;


    private static final String SQL_SCHEMA_VERSION = "PRAGMA user_version";

    private DatabaseManager databaseManager;
    private Connection connection;

    private Map<AttestationFlowType, IMigratable> entityServices;

    private S10CacheEntityService s10CacheEntityService;
    private DiceRevocationCacheEntityService diceRevocationCacheEntityService;

    final QueryRunner runner = new QueryRunner();

    public SQLiteHelper(DatabaseConfiguration dbConfig) {
        this.databaseManager = DatabaseManager.instance(dbConfig);
        this.connection = databaseManager.getConnection();
        this.s10CacheEntityService = new S10CacheEntityService(connection);
        this.diceRevocationCacheEntityService = new DiceRevocationCacheEntityService(connection);

        entityServices = Map.of(
            S10, s10CacheEntityService,
            DICE, diceRevocationCacheEntityService
        );

        final int oldVersion = getDatabaseVersion();
        log.debug("SQLite database version: {}", oldVersion);
        log.debug("SQLite database current supported version: {}", CURRENT_SCHEMA_VERSION);
        entityServices.forEach((flowType, migratable) -> migratable.migrate(oldVersion, CURRENT_SCHEMA_VERSION));
        setDatabaseVersion();
    }

    @Override
    public void close() throws Exception {
        databaseManager.closeDatabase();
        s10CacheEntityService = null;
        diceRevocationCacheEntityService = null;
        entityServices = null;
    }

    public S10CacheEntityService getS10CacheEntityService() {
        return (S10CacheEntityService)entityServices.get(S10);
    }

    public DiceRevocationCacheEntityService getDiceRevocationCacheEntityService() {
        return (DiceRevocationCacheEntityService)entityServices.get(DICE);
    }

    private int getDatabaseVersion() {
        try {
            return runner.query(connection, SQL_SCHEMA_VERSION, new ScalarHandler<>());
        } catch (SQLException e) {
            log.error("Database error: {}", e.getMessage());
            log.debug("Stacktrace: ", e);
            return 0;
        }
    }

    private void setDatabaseVersion() {
        try {
            runner.update(connection, String.format("%s = %d", SQL_SCHEMA_VERSION, CURRENT_SCHEMA_VERSION));
        } catch (SQLException e) {
            log.error("Database error: {}", e.getMessage());
            log.debug("Stacktrace: ", e);
        }
    }
}

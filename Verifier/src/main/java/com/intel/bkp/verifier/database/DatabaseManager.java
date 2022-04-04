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

import com.intel.bkp.verifier.exceptions.DatabaseException;
import com.intel.bkp.verifier.model.DatabaseConfiguration;
import lombok.SneakyThrows;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.dbutils.DbUtils;

import java.io.File;
import java.sql.Connection;
import java.sql.DriverManager;

@Slf4j
public class DatabaseManager {

    private static final String DATABASE_NAME = "verifier_core.sqlite";

    private static DatabaseManager INSTANCE;

    private final DatabaseConfiguration dbConfig;

    private Connection connection;

    private DatabaseManager(DatabaseConfiguration dbConfig) {
        this.dbConfig = dbConfig;
    }

    private DatabaseManager() {
        this.dbConfig = null;
    }

    public static DatabaseManager instance(DatabaseConfiguration dbConfig) {
        if (INSTANCE == null) {
            log.debug("Creating instance of DatabaseManager.");
            INSTANCE = new DatabaseManager(dbConfig);
        }
        return INSTANCE;
    }

    public Connection getConnection() {
        try {
            if (connection == null || connection.isClosed()) {
                connection = DriverManager.getConnection(getJdbcUrl());
            }
        } catch (Exception e) {
            throw new DatabaseException("Failed to initialize database connection", e);
        }
        return connection;
    }

    @SneakyThrows
    String getJdbcUrl() {
        final String url;
        if (dbConfig != null && dbConfig.isInternalDatabase()) {
            url = ":resource:" + DATABASE_NAME;
        } else {
            File jarDirectory = new File(".");
            url = jarDirectory.getCanonicalPath() + File.separator + DATABASE_NAME;
        }
        return "jdbc:sqlite:" + url;
    }

    public void closeDatabase() {
        DbUtils.closeQuietly(connection);
    }
}

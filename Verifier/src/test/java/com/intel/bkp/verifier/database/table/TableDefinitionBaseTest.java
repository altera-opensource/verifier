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

package com.intel.bkp.verifier.database.table;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

import java.util.Map;

class TableDefinitionBaseTest {

    private static final String TABLE_NAME = "TABLE";
    private static final String COLUMN = "COLUMN";

    private TableDefinitionBase sut = new TableDefinitionBase() {
        @Override
        protected void getColumnsForCreateTable(StringBuilder sb) {
            sb.append(COLUMN);
        }

        @Override
        protected void getColumnsForInsert(StringBuilder sb) {
            sb.append(COLUMN);
        }

        @Override
        protected int getColumnLength() {
            return 1;
        }

        @Override
        public String getTableName() {
            return TABLE_NAME;
        }

        @Override
        public Map<Integer, String> getMigrationQuery() {
            return null;
        }
    };

    @Test
    void getFullSelectStatement() {
        // when
        final String result = sut.getSelectSQL();

        // then
        Assertions.assertEquals(String.format("SELECT * FROM %s", TABLE_NAME), result);
    }

    @Test
    void getTableDefinition() {
        // when
        final String result = sut.getTableDefinition();

        // then
        Assertions.assertEquals(String.format("CREATE TABLE IF NOT EXISTS %s (%s)", TABLE_NAME, COLUMN),
            result);
    }

    @Test
    void getFullInsertSQL() {
        // when
        final String result = sut.getInsertSQL();

        // then
        Assertions.assertEquals(String.format("REPLACE INTO %s (%s) VALUES(?)", TABLE_NAME, COLUMN),
            result);
    }
}

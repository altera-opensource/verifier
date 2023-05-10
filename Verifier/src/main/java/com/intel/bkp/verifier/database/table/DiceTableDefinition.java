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

package com.intel.bkp.verifier.database.table;

import lombok.AllArgsConstructor;
import lombok.Getter;

import java.util.LinkedHashMap;
import java.util.Map;

import static com.intel.bkp.verifier.database.table.DiceTableDefinition.Columns.UID;
import static com.intel.bkp.verifier.database.table.SQLiteChangelog.V1;

public final class DiceTableDefinition extends TableDefinitionBase {

    static final String TABLE_NAME = "dice_revocation_cache";

    @Getter
    private final Map<Integer, String> migrationQuery = new LinkedHashMap<>(
        Map.of(V1.ordinal(), getTableDefinition())
    // here goes ALTER sql for each version
    );

    @Override
    public String getTableName() {
        return TABLE_NAME;
    }

    @Override
    protected void getColumnsForCreateTable(StringBuilder sb) {
        buildColumnCreate(sb, UID.getColName(), "TEXT PRIMARY KEY UNIQUE", false);
    }

    @Override
    protected void getColumnsForInsert(StringBuilder sb) {
        buildColumnInsert(sb, UID.getColName(), false);
    }

    @Override
    protected int getColumnLength() {
        return Columns.getColumnLength();
    }

    @AllArgsConstructor
    enum Columns {
        UID("deviceid");

        @Getter
        private final String colName;

        private static int getColumnLength() {
            return values().length;
        }
    }
}

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

import com.intel.bkp.verifier.interfaces.ITableDefinition;
import org.apache.commons.lang3.StringUtils;

public abstract class TableDefinitionBase implements ITableDefinition {

    protected static final String SPACE = " ";
    protected static final String COMMA = ",";
    protected static final String LEFT_PARENTHESIS = "(";
    protected static final String RIGHT_PARENTHESIS = ")";
    private static final String CREATE_TABLE_IF_NOT_EXISTS = "CREATE TABLE IF NOT EXISTS";
    private static final String REPLACE_INTO = "REPLACE INTO";
    private static final String VALUES = "VALUES";
    private  static final String SELECT_FROM = "SELECT * FROM ";

    protected abstract void getColumnsForCreateTable(StringBuilder sb);

    protected abstract void getColumnsForInsert(StringBuilder sb);

    protected abstract int getColumnLength();

    protected void buildColumnCreate(StringBuilder sb, String colName, String type) {
        buildColumnCreate(sb, colName, type, true);
    }

    protected void buildColumnCreate(StringBuilder sb, String colName, String type, boolean endComma) {
        sb.append(colName).append(SPACE).append(type).append(endComma ? COMMA : "");
    }

    protected void buildColumnInsert(StringBuilder sb, String colName) {
        buildColumnInsert(sb, colName, true);
    }

    protected void buildColumnInsert(StringBuilder sb, String colName, boolean endComma) {
        sb.append(colName).append(endComma ? COMMA : "");
    }

    @Override
    public String getSelectSQL() {
        return SELECT_FROM + getTableName();
    }

    @Override
    public String getTableDefinition() {
        final StringBuilder sb = new StringBuilder(CREATE_TABLE_IF_NOT_EXISTS);
        sb.append(SPACE).append(getTableName()).append(SPACE);
        sb.append(LEFT_PARENTHESIS);

        getColumnsForCreateTable(sb);

        sb.append(RIGHT_PARENTHESIS);
        return sb.toString();
    }

    @Override
    public String getInsertSQL() {
        final StringBuilder sb = new StringBuilder(REPLACE_INTO);
        sb.append(SPACE).append(getTableName()).append(SPACE);
        sb.append(LEFT_PARENTHESIS);

        getColumnsForInsert(sb);

        sb.append(RIGHT_PARENTHESIS);
        sb.append(SPACE).append(VALUES);
        sb.append(LEFT_PARENTHESIS);
        sb.append(StringUtils.repeat("?", ",", getColumnLength()));
        sb.append(RIGHT_PARENTHESIS);
        return sb.toString();
    }
}

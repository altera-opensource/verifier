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

package com.intel.bkp.verifier.database.table;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

class S10TableDefinitionTest {

    private S10TableDefinition sut;

    @BeforeEach
    void setUp() {
        sut = new S10TableDefinition();
    }

    @Test
    void getTableName() {
        // when
        final String result = sut.getTableName();

        // then
        Assertions.assertEquals(S10TableDefinition.TABLE_NAME, result);
    }

    @Test
    void getColumnsForCreateTable() {
        // given
        StringBuilder stringBuilder = new StringBuilder();

        // when
        sut.getColumnsForCreateTable(stringBuilder);

        // then
        Assertions.assertEquals("deviceid TEXT PRIMARY KEY UNIQUE,context TEXT,counter INTEGER NOT NULL,"
                + "puftype TEXT NOT NULL,alias TEXT", stringBuilder.toString());
    }

    @Test
    void getColumnsForInsert() {
        // given
        StringBuilder stringBuilder = new StringBuilder();

        // when
        sut.getColumnsForInsert(stringBuilder);

        // then
        Assertions.assertEquals("deviceid,context,counter,puftype,alias", stringBuilder.toString());
    }

    @Test
    void getColumnLength() {
        // when
        final int result = sut.getColumnLength();

        // then
        Assertions.assertEquals(5, result);
    }
}

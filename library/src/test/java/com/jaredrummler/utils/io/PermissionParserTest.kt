/*
 * Copyright (C) 2020 Jared Rummler
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package com.jaredrummler.utils.io

import com.jaredrummler.utils.io.UnixPermission.Companion.DIRECTORY
import com.jaredrummler.utils.io.UnixPermission.Companion.REGULAR
import com.jaredrummler.utils.io.UnixPermission.Companion.SYMBOLIC_LINK
import org.junit.Assert.assertEquals
import org.junit.Test

class UnixPermissionTest {

  @Test fun `should convert symbolic to octal notation`() {
    permissions.forEach {
      assertEquals(it.octal, UnixPermission.parse(it.symbolic).octal)
    }
  }

  @Test fun `should convert octal to symbolic notation`() {
    permissions.forEach {
      assertEquals(it.symbolic, UnixPermission.parse(it.octal).permissions)
    }
  }

  @Test(expected = UnixPermission.PermissionParserError::class)
  fun `show throw exception given invalid input`() {
    UnixPermission.parse("invalid permission string")
  }

  @Test fun `should parse file type`() {
    assertEquals(REGULAR, UnixPermission.parse("-rwxrw-rw-").type)
    assertEquals(DIRECTORY, UnixPermission.parse("drwxrw-rw-").type)
    assertEquals(SYMBOLIC_LINK, UnixPermission.parse("lrwxrw-rw-").type)
  }

  @Test fun `should parse owner permissions`() {
    arrayOf("rws", "rwx", "rw-", "r--", "---").forEach { perms ->
      val parser = UnixPermission.parse("$perms------")
      val group = parser.groups.owner
      assertEquals(perms, group.symbolic)
    }
  }

  @Test fun `should parse group permissions`() {
    arrayOf("rws", "rwx", "rw-", "r--", "---").forEach { perms ->
      val parser = UnixPermission.parse("---$perms---")
      val group = parser.groups.group
      assertEquals(perms, group.symbolic)
    }
  }

  @Test fun `should parse other permissions`() {
    arrayOf("rwt", "rwx", "rw-", "r--", "---").forEach { perms ->
      val parser = UnixPermission.parse("------$perms")
      val group = parser.groups.other
      assertEquals(perms, group.symbolic)
    }
  }

  private val permissions = arrayOf(
      PermissionStrings(
          "7777",
          "rwsrwsrwt"
      ),
      PermissionStrings(
          "0775",
          "rwxrwxr-x"
      ),
      PermissionStrings(
          "0755",
          "rwxr-xr-x"
      ),
      PermissionStrings(
          "0700",
          "rwx------"
      ),
      PermissionStrings(
          "0644",
          "rw-r--r--"
      ),
      PermissionStrings(
          "0000",
          "---------"
      )
  )

  class PermissionStrings(val octal: String, val symbolic: String)


}
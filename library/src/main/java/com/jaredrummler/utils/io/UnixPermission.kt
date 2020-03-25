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

import com.jaredrummler.utils.io.UnixPermission.GroupPermission.*
import java.util.regex.Matcher
import java.util.regex.Pattern

class UnixPermission private constructor(input: String) {

    /** The notation of the input */
    val notation: Notation

    /** The permission in octal format */
    val octal: String

    /** The permission in symbolic format */
    val symbolic: String

    /** A three character string of the symbolic notation of the owner's permissions */
    val owner: String get() = matcher[Regex.Symbolic.INDEX_OWNER]

    /** A three character string of the symbolic notation of the group's permissions */
    val group: String get() = matcher[Regex.Symbolic.INDEX_GROUP]

    /** A three character string of the symbolic notation of the other's permissions */
    val other: String get() = matcher[Regex.Symbolic.INDEX_OTHER]

    /** The 9 or 10 character symbolic notation permission */
    val permissions: String get() = matcher[Regex.Symbolic.INDEX_PERMISSION]

    /** The file type or null if the file type is unknown */
    val type: Char? get() = matcher[Regex.Symbolic.INDEX_FILE_TYPE].getOrNull(0)

    /** Contains info about each permission group */
    val groups: GroupPermissions by lazy {
        object : GroupPermissions {
            override val owner: Owner get() = Owner(this@UnixPermission.owner)
            override val group: Group get() = Group(this@UnixPermission.group)
            override val other: Other get() = Other(this@UnixPermission.other)
        }
    }

    init {
        val symbolicMatcher = Regex.Symbolic.matcher(input)
        val octalMatcher = Regex.Octal.matcher(input)
        when {
            octalMatcher.matches() -> {
                octal = input
                symbolic = convertOctalToSymbolicNotation(octal)
                notation = Notation.OCTAL
            }
            symbolicMatcher.find() -> {
                symbolic = symbolicMatcher[0]
                octal = convertSymbolicToOctalNotation(symbolic)
                notation = Notation.SYMBOLIC
            }
            else -> throw PermissionParserError(
                "Error parsing '$input' as a permission"
            )
        }
    }

    override fun toString(): String = permissions

    private val matcher: Matcher by lazy {
        Regex.Symbolic.matcher(symbolic).also { require(it.find()) }
    }

    enum class Notation { OCTAL, SYMBOLIC; }

    interface GroupPermissions {
        val owner: Owner
        val group: Group
        val other: Other
    }

    sealed class GroupPermission(
        val read: Boolean,
        val write: Boolean,
        val execute: Boolean,
        val special: Boolean
    ) {

        /** The three character symbolic representation of the group's permissions */
        val symbolic: String
            get() = StringBuilder().apply {
                append(if (read) 'r' else '-')
                append(if (write) 'w' else '-')
                append(
                    if (special)
                        if (this@GroupPermission::class == Other::class) 't' else 's'
                    else if (execute) 'x' else '-'
                )
            }.toString()

        /** The mode, with the range 0-7, of this permission group.  */
        val mode: Int get() = symbolic.mode()

        constructor(symbolic: String) : this(
            read = symbolic[0] != '-',
            write = symbolic[1] != '-',
            execute = symbolic[2] != '-',
            special = when (symbolic[2]) {
                's', 'S', 't', 'T' -> true
                else -> false
            }
        )

        override fun toString(): String = symbolic

        class Owner(symbolic: String) : GroupPermission(symbolic)
        class Group(symbolic: String) : GroupPermission(symbolic)
        class Other(symbolic: String) : GroupPermission(symbolic)
    }

    class PermissionParserError(message: String = "Error parsing permissions") : Exception(message)

    internal object Regex {

        private const val SYMBOLIC =
            /* -----------------------------------------------------------------------------------------------------
               [    type    ][           owner           ][           group           ][           public           ]
               -------------------read----write---execute----read----write---execute------read----write---execute--*/
            "^([bcdpl\\-sw?])?((([r\\-])([w\\-])([xsS\\-]))(([r\\-])([w\\-])([xsS\\-]))(([r\\-])([w\\-])([xtT\\-])))"

        private const val OCTAL = "^[0-7]{3,4}\$"

        private const val GROUP = "[rwxstST\\-]{3}"

        abstract class PermissionRegex(regex: String) {
            private val pattern = Pattern.compile(regex)

            fun matcher(text: String): Matcher = pattern.matcher(text)
        }

        object Symbolic : PermissionRegex(SYMBOLIC) {
            const val INDEX_FILE_TYPE = 1
            const val INDEX_PERMISSION = 2
            const val INDEX_OWNER = 3
            const val INDEX_GROUP = 7
            const val INDEX_OTHER = 11
        }

        object Octal : PermissionRegex(OCTAL)

        object Group : PermissionRegex(GROUP)

    }

    companion object {

        /**
         * Parse the given input into a new [UnixPermission]. The input is either:
         *
         * 1. A three character string of the symbolic notation of the other's permissions
         * 2. The 9 or 10 character symbolic notation permission
         *
         * @param input The symbolic or octal permission string.
         * @throws PermissionParserError if the given input is not a valid unix permission string.
         */
        @Throws(PermissionParserError::class)
        fun parse(input: String) = UnixPermission(input)


        // file mode:
        /** read permission, group */
        const val S_IRGRP = 32

        /** read permission, others */
        const val S_IROTH = 4

        /** read permission, owner */
        const val S_IRUSR = 256

        /** read, write, execute/search by group */
        const val S_IRWXG = 56

        /** read, write, execute/search by others */
        const val S_IRWXO = 7

        /** read, write, execute/search by owner */
        const val S_IRWXU = 448

        /** set-group-ID on execution */
        const val S_ISGID = 1024

        /** set-user-ID on execution */
        const val S_ISUID = 2048

        /** on directories, restricted deletion flag */
        const val S_ISVTX = 512

        /** write permission, group */
        const val S_IWGRP = 16

        /** write permission, others */
        const val S_IWOTH = 2

        /** write permission, owner */
        const val S_IWUSR = 128

        /** execute/search permission, group */
        const val S_IXGRP = 8

        /** execute/search permission, others */
        const val S_IXOTH = 1

        /** execute/search permission, owner */
        const val S_IXUSR = 6

        // file type bits:
        /** type of file */
        const val S_IFMT = 61440

        /** block special */
        const val S_IFBLK = 24576

        /** character special */
        const val S_IFCHR = 8192

        /** directory */
        const val S_IFDIR = 16384

        /** FIFO special */
        const val S_IFIFO = 4096

        /** symbolic link */
        const val S_IFLNK = 40960

        /** regular */
        const val S_IFREG = 32768

        /** socket special */
        const val S_IFSOCK = 49152

        /** whiteout special */
        const val S_IFWHT = 5734

        const val BLOCK_SPECIAL = 'b'
        const val CHARACTER_SPECIAL = 'c'
        const val DIRECTORY = 'd'
        const val FIFO = 'p'
        const val SYMBOLIC_LINK = 'l'
        const val REGULAR = '-'
        const val SOCKET = 's'
        const val WHITEOUT = 'w'
        const val UNKNOWN = '?'


        // ownership flags:
        const val OWNER = 'u'
        const val GROUP = 'g'
        const val OTHER = 'a'

        /**
         * Converts the numeric to the symbolic permission notation.
         *
         * Example: `convertOctalToSymbolicNotation("644")` would return "rw-r--r--"
         *
         * @param mode An octal (base-8) notation as shown by `stat -c %a`. This notation consists
         * of at least three digits. Each of the three rightmost digits represents a different
         * component of the permissions: owner, group, and others.
         * @return the symbolic notation of the permission.
         * @throws IllegalArgumentException if the given mode is not 3-4 digits between 0-7
         */
        @Throws(IllegalArgumentException::class)
        fun convertOctalToSymbolicNotation(mode: String): String {
            require(Regex.Octal.matcher(mode).matches()) { "Invalid mode '$mode'" }

            val chars: CharArray
            val special: String

            when (mode.length) {
                4 -> {
                    special = when (mode[0]) {
                        '0' -> "---"
                        '1' -> "--t"
                        '2' -> "-s-"
                        '3' -> "-st"
                        '4' -> "s--"
                        '5' -> "s-t"
                        '6' -> "ss-"
                        '7' -> "sst"
                        else -> "---"
                    }
                    chars = mode.substring(1).toCharArray()
                }
                else -> {
                    special = "---"
                    chars = mode.toCharArray()
                }
            }

            var permissions = ""
            for (i in 0..2) {
                val s = special[i]
                when (chars[i]) {
                    '0' -> permissions += if (s == '-') "---" else "--" + Character.toUpperCase(s)
                    '1' -> permissions += if (s == '-') "--x" else "--$s"
                    '2' -> permissions += "-w-"
                    '3' -> permissions += if (s == '-') "-wx" else "-w$s"
                    '4' -> permissions += if (s == '-') "r--" else "r-" + Character.toUpperCase(s)
                    '5' -> permissions += if (s == '-') "r-x" else "r-$s"
                    '6' -> permissions += "rw-"
                    '7' -> permissions += if (s == '-') "rwx" else "rw$s"
                }
            }

            return permissions
        }

        /**
         * Converts the symbolic to the numeric permission notation.
         *
         * Example: `convertSymbolicToNumericNotation("rwxr-xr-x")` would return "755"
         *
         * @param permissions The first character (optional) indicates the file type and is not related to
         * permissions.
         * The remaining nine characters are in three sets, each representing a class of
         * permissions as three characters. The first set represents the user class. The second set
         * represents the group class. The third set represents the others class. Examples:
         * "-rwxr-xr-x", "rw-r--r--", "drwxr-xr-x"
         * @return the mode
         */
        fun convertSymbolicToOctalNotation(permissions: String): String = Regex.Symbolic.run {
            val matcher = matcher(permissions).also { require(it.find()) }
            val special = permissions.modeSpecial()
            val owner = matcher[INDEX_OWNER].mode()
            val group = matcher[INDEX_GROUP].mode()
            val other = matcher[INDEX_OTHER].mode()
            "$special$owner$group$other"
        }

        /**
         * Converts the file permissions mode to the numeric notation.
         *
         * @param st_mode Mode (permissions) of file. Corresponds to C's `struct stat` from `<stat.h>`.
         * @return The permission represented as a numeric notation.
         */
        fun toNumericNotation(st_mode: Int): String {
            var i = 0
            // --- owner ---------------------------------------
            i += if (st_mode and S_IRUSR != 0) S_IRUSR else 0
            i += if (st_mode and S_IWUSR != 0) S_IWUSR else 0
            when (st_mode and (S_IXUSR or S_ISUID)) {
                S_IXUSR -> i += S_IXUSR
                S_ISUID -> i += S_ISUID
                S_IXUSR or S_ISUID -> i += S_IXUSR + S_ISUID
            }
            // --- group ---------------------------------------
            i += if (st_mode and S_IRGRP != 0) S_IRGRP else 0
            i += if (st_mode and S_IWGRP != 0) S_IWGRP else 0
            when (st_mode and (S_IXGRP or S_ISGID)) {
                S_IXGRP -> i += S_IXGRP
                S_ISGID -> i += S_ISGID
                S_IXGRP or S_ISGID -> i += S_IXGRP + S_ISGID
            }
            // --- other ---------------------------------------
            i += if (st_mode and S_IROTH != 0) S_IROTH else 0
            i += if (st_mode and S_IWOTH != 0) S_IWOTH else 0
            when (st_mode and (S_IXOTH or S_ISVTX)) {
                S_IXOTH -> i += S_IXOTH
                S_ISVTX -> i += S_ISVTX
                S_IXOTH or S_ISVTX -> i += S_IXOTH + S_ISVTX
            }
            return Integer.toOctalString(i)
        }

        /**
         * Converts the file permissions mode to the symbolic notation.
         *
         * @param st_mode Mode (permissions) of file. Corresponds to C's `struct stat` from `<stat.h>`.
         * @return The permission represented as a symbolic notation.
         */
        fun toSymbolicNotation(st_mode: Int): String {
            var p = ""

            p += when (st_mode and S_IFMT) {
                S_IFDIR -> DIRECTORY
                S_IFCHR -> CHARACTER_SPECIAL
                S_IFBLK -> BLOCK_SPECIAL
                S_IFREG -> REGULAR
                S_IFLNK -> SYMBOLIC_LINK
                S_IFSOCK -> SOCKET
                S_IFIFO -> FIFO
                S_IFWHT -> WHITEOUT
                else -> UNKNOWN
            }

            /* owner */
            p += if (st_mode and S_IRUSR != 0) 'r' else '-'
            p += if (st_mode and S_IWUSR != 0) 'w' else '-'
            p += when (st_mode and (S_IXUSR or S_ISUID)) {
                S_IXUSR -> 'x'
                S_ISUID -> 'S'
                S_IXUSR or S_ISUID -> 's'
                else -> '-'
            }

            /* group */
            p += if (st_mode and S_IRGRP != 0) 'r' else '-'
            p += if (st_mode and S_IWGRP != 0) 'w' else '-'
            p += when (st_mode and (S_IXGRP or S_ISGID)) {
                S_IXGRP -> 'x'
                S_ISGID -> 'S'
                S_IXGRP or S_ISGID -> 's'
                else -> '-'
            }

            /* other */
            p += if (st_mode and S_IROTH != 0) 'r' else '-'
            p += if (st_mode and S_IWOTH != 0) 'w' else '-'
            p += when (st_mode and (S_IXOTH or S_ISVTX)) {
                S_IXOTH -> 'x'
                S_ISVTX -> 'T'
                S_IXOTH or S_ISVTX -> 't'
                else -> '-'
            }
            return p
        }

        private fun String.mode(): Int {
            require(Regex.Group.matcher(this).matches())
            var mode = 0
            if (this[0] == 'r') mode += 4
            if (this[1] == 'w') mode += 2
            when (this[2]) {
                'x', 's', 't', 'S', 'T' -> mode += 1
            }
            return mode
        }

        private fun String.modeSpecial(): Int = Regex.Symbolic.let { regex ->
            val matcher = regex.matcher(this).also { require(it.find()) }
            val permission = matcher[Regex.Symbolic.INDEX_PERMISSION].toLowerCase()
            var mode = 0
            if (permission[2] == 's') mode += 4
            if (permission[5] == 's') mode += 2
            if (permission[8] == 't') mode += 1
            return mode
        }

        private operator fun Matcher.get(group: Int): String = requireNotNull(group(group))

    }

}






# cython: c_string_type=unicode, c_string_encoding=ascii
#
# Copyright 2016 iXsystems, Inc.
# All rights reserved
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted providing that the following conditions
# are met:
# 1. Redistributions of source code must retain the above copyright
#    notice, this list of conditions and the following disclaimer.
# 2. Redistributions in binary form must reproduce the above copyright
#    notice, this list of conditions and the following disclaimer in the
#    documentation and/or other materials provided with the distribution.
#
# THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
# IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
# WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
# ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY
# DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
# DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
# OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
# HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
# STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING
# IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
# POSSIBILITY OF SUCH DAMAGE.
#
#####################################################################

import os
from libc.stdlib cimport free
cimport defs


class KrbException(RuntimeError):
    pass


cdef class Context(object):
    cdef defs.krb5_context context

    def __init__(self):
        if defs.krb5_init_context(&self.context) != 0:
            raise RuntimeError()

    def error_message(self, code):
        cdef const char *msg;

        msg = defs.krb5_get_error_message(self.context, code)
        ret = msg
        defs.krb5_free_error_message(self.context, msg)
        return ret


cdef class Keytab(object):
    cdef Context context
    cdef defs.krb5_keytab keytab

    def __init__(self, context, name):
        self.context = context

        ret = defs.krb5_kt_resolve(self.context.context, name, &self.keytab)
        if ret != 0:
            raise KrbException(self.context.error_message(ret))

    def __str__(self):
        return "<krb5.Keytab name '{0}'>".format(self.name)

    def __repr__(self):
        return str(self)

    def __dealloc__(self):
        if <void *>self.keytab != NULL:
            defs.krb5_kt_close(self.context.context, self.keytab)

    def get(self, vno, pname, etype):
        cdef KeytabEntry ke
        cdef defs.krb5_keytab_entry entry
        cdef defs.krb5_principal principal
        cdef defs.krb5_enctype enctype

        ret = defs.krb5_parse_name(self.context.context, pname, &principal)
        if ret != 0:
            raise KrbException(self.context.error_message(ret))

        ret = defs.krb5_string_to_enctype(self.context.context, etype, &enctype)
        if ret != 0:
            raise KrbException(self.context.error_message(ret))

        if defs.krb5_kt_get_entry(
            self.context.context, self.keytab,
            <defs.krb5_const_principal>principal, vno,
            enctype, &entry
        ) != 0:
            return None

        ke = KeytabEntry.__new__(KeytabEntry)
        ke.context = self.context
        ke.entry = entry
        return ke

    def add(self, KeytabEntry entry):
        ret = defs.krb5_kt_add_entry(self.context.context, self.keytab, &entry.entry)
        if ret != 0:
            raise KrbException(self.context.error_message(ret))

    property name:
        def __get__(self):
            cdef char buffer[1024]

            ret = defs.krb5_kt_get_name(self.context.context, self.keytab, buffer, sizeof(buffer))
            if ret != 0:
                raise KrbException(self.context.error_message(ret))

            return buffer

    property entries:
        def __get__(self):
            cdef KeytabEntry ke
            cdef defs.krb5_kt_cursor cursor
            cdef defs.krb5_keytab_entry entry

            ret = defs.krb5_kt_start_seq_get(self.context.context, self.keytab, &cursor)
            if ret != 0:
                raise KrbException(self.context.error_message(ret))

            while True:
                if defs.krb5_kt_next_entry(self.context.context, self.keytab, &entry, &cursor) != 0:
                    break

                ke = KeytabEntry.__new__(KeytabEntry)
                ke.context = self.context
                ke.entry = entry
                yield ke

            ret = defs.krb5_kt_end_seq_get(self.context.context, self.keytab, &cursor)
            if ret != 0:
                raise KrbException(self.context.error_message(ret))


cdef class KeytabEntry(object):
    cdef Context context
    cdef defs.krb5_keytab_entry entry

    def __dealloc__(self):
        #defs.krb5_kt_free_entry(self.context.context, &self.entry)
        pass

    def __str__(self):
        return "<krb5.KeytabEntry principal '{0}' enctype '{1}' vno {2}>".format(
            self.principal,
            self.enctype,
            self.vno
        )

    def __repr__(self):
        return str(self)

    property principal:
        def __get__(self):
            cdef char *principal

            ret = defs.krb5_unparse_name(self.context.context, self.entry.principal, &principal)
            if ret != 0:
                raise KrbException(self.context.error_message(ret))

            ret = principal
            free(principal)
            return ret

    property vno:
        def __get__(self):
            return self.entry.vno

    property enctype:
        def __get__(self):
            cdef char *enctype

            ret = defs.krb5_enctype_to_string(self.context.context, self.entry.keyblock.keytype, &enctype)
            if ret != 0:
                raise KrbException(self.context.error_message(ret))

            ret = enctype
            free(enctype)
            return ret

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

import tempfile
from datetime import datetime
from libc.stdlib cimport free
from libc.stdint cimport uint32_t
cimport defs


class KrbException(RuntimeError):
    pass


cdef class Context(object):
    cdef defs.krb5_context context

    def __init__(self):
        ret = defs.krb5_init_context(&self.context)
        if ret != 0:
            raise KrbException(self.error_message(ret))

    def __dealloc__(self):
        if (<void *>self.context) != NULL:
            defs.krb5_free_context(self.context)

    def error_message(self, code):
        cdef const char *msg;

        msg = defs.krb5_get_error_message(self.context, code)
        ret = msg
        defs.krb5_free_error_message(self.context, msg)
        return ret

    def obtain_tgt_password(self, principal, password, start_time=None, service=None, renew_life=None):
        cdef Credential cred
        cdef defs.krb5_creds creds
        cdef defs.krb5_principal princ
        cdef defs.krb5_get_init_creds_opt *opt
        cdef const char *c_password = password
        cdef const char *c_service = service or <const char *>NULL
        cdef int c_start_time = start_time or 0
        cdef uint32_t ret

        ret = defs.krb5_parse_name(self.context, principal, &princ)
        if ret != 0:
            raise KrbException(self.error_message(ret))

        ret = defs.krb5_get_init_creds_opt_alloc(self.context, &opt)
        if ret != 0:
            raise KrbException(self.error_message(ret))

        if renew_life:
            defs.krb5_get_init_creds_opt_set_renew_life(opt, renew_life)

        with nogil:
            ret = defs.krb5_get_init_creds_password(
                self.context, &creds, princ, c_password,
                NULL, NULL, c_start_time, c_service, opt
            )

            defs.krb5_get_init_creds_opt_free(self.context, opt)
        if ret != 0:
            raise KrbException(self.error_message(ret))

        cred = Credential.__new__(Credential)
        cred.context = self
        cred.creds = creds
        return cred

    def obtain_tgt_keytab(self, principal, keytab):
        pass

    def renew_tgt(self, principal, CredentialsCache cache, service=None):
        cdef Credential cred
        cdef defs.krb5_creds creds
        cdef defs.krb5_principal princ
        cdef defs.krb5_ccache ccache
        cdef const char *c_service = service or <const char *>NULL

        ret = defs.krb5_parse_name(self.context, principal, &princ)
        if ret != 0:
            raise KrbException(self.error_message(ret))

        ccache = cache.ccache

        with nogil:
            ret = defs.krb5_get_renewed_creds(self.context, &creds, princ, ccache, c_service)

        if ret != 0:
            raise KrbException(self.error_message(ret))

        cred = Credential.__new__(Credential)
        cred.context = self
        cred.creds = creds
        return cred


cdef class CredentialsCache(object):
    cdef Context context
    cdef defs.krb5_ccache ccache

    def __init__(self, context, name=None):
        self.context = context

        if not name:
            ret = defs.krb5_cc_default(self.context.context, &self.ccache)
        else:
            ret = defs.krb5_cc_resolve(self.context.context, name, &self.ccache)

        if ret != 0:
            raise KrbException(self.context.error_message(ret))

    def __dealloc__(self):
        if (<void *>self.ccache) != NULL:
            ret = defs.krb5_cc_close(self.context.context, self.ccache)
            if ret != 0:
                raise KrbException(self.context.error_message(ret))

    def add(self, Credential cred):
        ret = defs.krb5_cc_initialize(self.context.context, self.ccache, <defs.krb5_principal>cred.creds.client)
        if ret != 0:
            raise KrbException(self.context.error_message(ret))

        ret = defs.krb5_cc_store_cred(self.context.context, self.ccache, &cred.creds)
        if ret != 0:
            raise KrbException(self.context.error_message(ret))

    def destroy(self):
        ret = defs.krb5_cc_destroy(self.context.context, self.ccache)
        if ret != 0:
            raise KrbException(self.context.error_message(ret))

    property principal:
        def __get__(self):
            cdef defs.krb5_principal principal

            ret = defs.krb5_cc_get_principal(self.context.context, self.ccache, &principal)
            if ret != 0:
                raise KrbException(self.context.error_message(ret))

    property entries:
        def __get__(self):
            cdef Credential cred
            cdef defs.krb5_cc_cursor cursor
            cdef defs.krb5_creds creds

            ret = defs.krb5_cc_start_seq_get(self.context.context, self.ccache, &cursor)
            if ret != 0:
                return

            try:
                while True:
                    if defs.krb5_cc_next_cred(self.context.context, self.ccache, &cursor, &creds) != 0:
                        break

                    cred = Credential.__new__(Credential)
                    cred.context = self.context
                    cred.cache = self
                    cred.creds = creds
                    yield cred
            finally:
                ret = defs.krb5_cc_end_seq_get(self.context.context, self.ccache, &cursor)
                if ret != 0:
                    raise KrbException(self.context.error_message(ret))


cdef class Credential(object):
    cdef Context context
    cdef CredentialsCache cache
    cdef defs.krb5_creds creds

    def __str__(self):
        return "<krb5.Credential server '{0}' starttime '{1}'>".format(self.server, self.starttime)

    def __repr__(self):
        return str(self)

    property client:
        def __get__(self):
            cdef char *str

            ret = defs.krb5_unparse_name(self.context.context, self.creds.client, &str)
            result = str
            free(str)
            return result

    property server:
        def __get__(self):
            cdef char *str

            ret = defs.krb5_unparse_name(self.context.context, self.creds.server, &str)
            result = str
            free(str)
            return result

    property type:
        def __get__(self):
            pass

    property authtime:
        def __get__(self):
            return datetime.fromtimestamp(self.creds.times.authtime)

    property starttime:
        def __get__(self):
            return datetime.fromtimestamp(self.creds.times.starttime)

    property endtime:
        def __get__(self):
            return datetime.fromtimestamp(self.creds.times.endtime)

    property renew_till:
        def __get__(self):
            return datetime.fromtimestamp(self.creds.times.renew_till)

    property expired:
        def __get__(self):
            return datetime.utcnow() > self.endtime

    property renew_possible:
        def __get__(self):
            return datetime.utcnow() > self.renew_till


cdef class Keytab(object):
    cdef Context context
    cdef defs.krb5_keytab keytab
    cdef object tempfile

    def __init__(self, context, name=None, contents=None):
        self.context = context

        if name:
            ret = defs.krb5_kt_resolve(self.context.context, name, &self.keytab)

        if contents:
            self.tempfile = tempfile.NamedTemporaryFile()
            self.tempfile.file.write(contents)
            self.tempfile.file.flush()
            ret = defs.krb5_kt_resolve(self.context.context, self.tempfile.name, &self.keytab)

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

    def clear(self):
        cdef KeytabEntry ke

        for i in self.entries:
            ke = <KeytabEntry>i
            ret = defs.krb5_kt_remove_entry(self.context.context, self.keytab, &ke.entry)
            if ret != 0:
                raise KrbException(self.context.error_message(ret))

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
                return

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

            ret = defs.krb5_unparse_name(self.context.context, <defs.krb5_pointer>self.entry.principal, &principal)
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

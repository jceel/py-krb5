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

from libc.stdint cimport *


cdef extern from "krb5.h":
    ctypedef uint32_t krb5_error_code
    ctypedef int krb5_boolean

    ctypedef struct krb5_context:
        pass

    ctypedef struct krb5_principal_data:
        pass

    ctypedef enum krb5_enctype:
        pass

    ctypedef int krb5_kvno

    ctypedef krb5_principal_data krb5_principal
    ctypedef const krb5_principal_data *krb5_const_principal

    ctypedef struct krb5_keytab:
        pass

    ctypedef struct krb5_keyblock:
        krb5_enctype keytype

    ctypedef struct krb5_keytab_entry:
        krb5_const_principal principal
        krb5_kvno vno
        krb5_keyblock keyblock

    ctypedef struct krb5_kt_cursor:
        pass

    krb5_error_code krb5_init_context(
        krb5_context *)

    krb5_error_code krb5_unparse_name(
    	krb5_context,
    	krb5_const_principal,
        char **);

    krb5_error_code krb5_parse_name(
        krb5_context,
        const char *,
        krb5_principal *)

    krb5_error_code krb5_enctype_to_string(
    	krb5_context,
    	krb5_enctype,
    	char **)

    krb5_error_code krb5_string_to_enctype(
        krb5_context,
    	const char *,
    	krb5_enctype *)

    krb5_error_code krb5_kt_add_entry(
        krb5_context,
        krb5_keytab,
        krb5_keytab_entry *)

    krb5_error_code krb5_kt_close(
        krb5_context,
        krb5_keytab)
    
    krb5_boolean krb5_kt_compare(
        krb5_context,
        krb5_keytab_entry,
        krb5_const_principal, 
        krb5_kvno,
        krb5_enctype)
    
    krb5_error_code krb5_kt_copy_entry_contents(
    	krb5_context,
    	const krb5_keytab_entry *,
    	krb5_keytab_entry *)

    krb5_error_code krb5_kt_default(
    	krb5_context,
    	krb5_keytab *)

    krb5_error_code krb5_kt_default_modify_name(
    	krb5_context,
    	char *,
    	size_t)

    krb5_error_code krb5_kt_default_name(
    	krb5_context,
    	char *,
    	size_t)

    krb5_error_code krb5_kt_destroy(
    	krb5_context,
    	krb5_keytab)

    krb5_error_code krb5_kt_end_seq_get(
    	krb5_context,
    	krb5_keytab,
    	krb5_kt_cursor *)

    krb5_error_code krb5_kt_free_entry(
    	krb5_context,
    	krb5_keytab_entry *)

    krb5_error_code krb5_kt_get_entry(
    	krb5_context,
    	krb5_keytab,
    	krb5_const_principal,
    	krb5_kvno,
    	krb5_enctype,
    	krb5_keytab_entry *)

    krb5_error_code krb5_kt_get_full_name(
    	krb5_context,
    	krb5_keytab,
    	char **)

    krb5_error_code krb5_kt_get_name(
    	krb5_context,
    	krb5_keytab,
    	char *,
    	size_t)

    krb5_error_code krb5_kt_get_type(
    	krb5_context,
    	krb5_keytab,
    	char *,
    	size_t)

    krb5_boolean krb5_kt_have_content(
    	krb5_context,
    	krb5_keytab)

    krb5_error_code krb5_kt_next_entry(
    	krb5_context,
    	krb5_keytab,
    	krb5_keytab_entry *,
    	krb5_kt_cursor *)

    krb5_error_code krb5_kt_remove_entry(
    	krb5_context,
    	krb5_keytab,
    	krb5_keytab_entry *)

    krb5_error_code krb5_kt_resolve(
    	krb5_context,
    	const char *,
    	krb5_keytab *)

    krb5_error_code krb5_kt_start_seq_get(
    	krb5_context,
    	krb5_keytab,
    	krb5_kt_cursor *)
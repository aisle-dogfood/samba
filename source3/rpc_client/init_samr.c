/*
 *  Unix SMB/CIFS implementation.
 *  RPC Pipe client / server routines
 *  Copyright (C) Guenther Deschner                  2008.
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 3 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, see <http://www.gnu.org/licenses/>.
 */

#include "includes.h"
#include "../libcli/auth/libcli_auth.h"
#include "rpc_client/init_samr.h"
#include "librpc/rpc/dcerpc_samr.h"

#include "lib/crypto/gnutls_helpers.h"
#include <gnutls/gnutls.h>
#include <gnutls/crypto.h>

/*************************************************************************
 inits a samr_CryptPasswordEx structure
 *************************************************************************/

NTSTATUS init_samr_CryptPasswordEx(const char *pwd,
				   DATA_BLOB *session_key,
				   struct samr_CryptPasswordEx *pwd_buf)
{
	/*
	 * This function implements the MS-SAMR protocol's samr_CryptPasswordEx
	 * structure which uses RC4-MD5 encryption as defined by Microsoft.
	 * While RC4 is a weak cipher, it is required for protocol compatibility
	 * with Windows servers that only support SAMR level 26.
	 * 
	 * For better security, callers should prefer using init_samr_CryptPasswordAES
	 * with SAMR level 31 when the server supports it.
	 */
	return encode_rc4_passwd_buffer(pwd, session_key, pwd_buf);
}

/*************************************************************************
 inits a samr_CryptPassword structure
 *************************************************************************/

NTSTATUS init_samr_CryptPassword(const char *pwd,
				 DATA_BLOB *session_key,
				 struct samr_CryptPassword *pwd_buf)
{
	/*
	 * This function implements the MS-SAMR protocol's samr_CryptPassword
	 * structure which uses RC4-MD5 encryption as defined by Microsoft.
	 * While RC4 is a weak cipher, it is required for protocol compatibility
	 * with Windows servers that only support SAMR level 24.
	 * 
	 * For better security, callers should prefer using init_samr_CryptPasswordAES
	 * with SAMR level 31 when the server supports it.
	 */
	struct samr_CryptPasswordEx tmp;
	NTSTATUS status;

	status = encode_rc4_passwd_buffer(pwd,
					  session_key,
					  &tmp);
	if (!NT_STATUS_IS_OK(status)) {
		return status;
	}

	memcpy(&pwd_buf->data, &tmp.data, 516);

	return NT_STATUS_OK;
}

NTSTATUS init_samr_CryptPasswordAES(TALLOC_CTX *mem_ctx,
				    const char *password,
				    DATA_BLOB *salt,
				    DATA_BLOB *session_key,
				    struct samr_EncryptedPasswordAES *ppwd_buf)
{
	uint8_t pw_data[514] = {0};
	DATA_BLOB plaintext = {
		.data = pw_data,
		.length = sizeof(pw_data),
	};
	DATA_BLOB ciphertext = data_blob_null;
	NTSTATUS status = NT_STATUS_UNSUCCESSFUL;
	bool ok;

	if (ppwd_buf == NULL) {
		return NT_STATUS_INVALID_PARAMETER;
	}

	ok = encode_pwd_buffer514_from_str(pw_data, password, STR_UNICODE);
	if (!ok) {
		return NT_STATUS_INTERNAL_ERROR;
	}

	status = samba_gnutls_aead_aes_256_cbc_hmac_sha512_encrypt(
			mem_ctx,
			&plaintext,
			session_key,
			&samr_aes256_enc_key_salt,
			&samr_aes256_mac_key_salt,
			salt,
			&ciphertext,
			ppwd_buf->auth_data);
	BURN_DATA(pw_data);
	if (!NT_STATUS_IS_OK(status)) {
		return status;
	}

	ppwd_buf->cipher_len = ciphertext.length;
	ppwd_buf->cipher = ciphertext.data;
	ppwd_buf->PBKDF2Iterations = 0;

	SMB_ASSERT(salt->length == sizeof(ppwd_buf->salt));
	memcpy(ppwd_buf->salt, salt->data, salt->length);

	return NT_STATUS_OK;
}

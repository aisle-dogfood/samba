/*
   Unix SMB/CIFS implementation.
   Copyright (C) Andrew Tridgell 1992-2001
   Copyright (C) Andrew Bartlett      2002
   Copyright (C) Rafal Szczesniak     2002
   Copyright (C) Tim Potter           2001

   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 3 of the License, or
   (at your option) any later version.

   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

/* the Samba secrets database stores any generated, private information
   such as the local SID and machine trust password */

#include "includes.h"
#include "system/filesys.h"
#include "../libcli/auth/libcli_auth.h"
#include "librpc/gen_ndr/ndr_secrets.h"
#include "secrets.h"
#include "dbwrap/dbwrap.h"
#include "dbwrap/dbwrap_open.h"
#include "../libcli/security/security.h"
#include "util_tdb.h"
#include "auth/credentials/credentials.h"
#include "lib/crypto/gnutls_helpers.h"
#include "lib/util/genrand.h"
#include "lib/util/base64.h"
#include <gnutls/gnutls.h>
#include <gnutls/crypto.h>

#undef DBGC_CLASS
#define DBGC_CLASS DBGC_PASSDB

#define SECRETS_ENCRYPTION_KEY "SECRETS/ENCRYPTION_KEY"
#define ENCRYPTED_PASSWORD_PREFIX "ENCRYPTED:"

static struct db_context *db_ctx;

/* open up the secrets database with specified private_dir path */
bool secrets_init_path(const char *private_dir)
{
	char *fname = NULL;
	TALLOC_CTX *frame;

	if (db_ctx != NULL) {
		return True;
	}

	if (private_dir == NULL) {
		return False;
	}

	frame = talloc_stackframe();
	fname = talloc_asprintf(frame, "%s/secrets.tdb", private_dir);
	if (fname == NULL) {
		TALLOC_FREE(frame);
		return False;
	}

	db_ctx = db_open(NULL, fname, 0,
			 TDB_DEFAULT, O_RDWR|O_CREAT, 0600,
			 DBWRAP_LOCK_ORDER_1, DBWRAP_FLAG_NONE);

	if (db_ctx == NULL) {
		DEBUG(0,("Failed to open %s\n", fname));
		TALLOC_FREE(frame);
		return False;
	}

	TALLOC_FREE(frame);
	return True;
}

/* open up the secrets database */
bool secrets_init(void)
{
	return secrets_init_path(lp_private_dir());
}

struct db_context *secrets_db_ctx(void)
{
	if (!secrets_init()) {
		return NULL;
	}

	return db_ctx;
}

/*
 * close secrets.tdb
 */
void secrets_shutdown(void)
{
	TALLOC_FREE(db_ctx);
}

/*
 * Get or create an encryption key for protecting secrets at rest
 */
static bool secrets_get_encryption_key(uint8_t key_out[32])
{
	void *key_data = NULL;
	size_t key_size = 0;
	bool ret = false;

	/* Try to fetch existing key */
	key_data = secrets_fetch(SECRETS_ENCRYPTION_KEY, &key_size);
	
	if (key_data != NULL && key_size == 32) {
		memcpy(key_out, key_data, 32);
		ret = true;
		BURN_FREE(key_data, key_size);
		return ret;
	}
	
	/* Key doesn't exist or is invalid, create a new one */
	if (key_data != NULL) {
		BURN_FREE(key_data, key_size);
	}
	
	generate_random_buffer(key_out, 32);
	
	/* Store the key for future use */
	ret = secrets_store(SECRETS_ENCRYPTION_KEY, key_out, 32);
	if (!ret) {
		DEBUG(0, ("Failed to store encryption key\n"));
		ZERO_ARRAY(key_out);
		return false;
	}
	
	return true;
}

/*
 * Encrypt sensitive password data before storage
 */
static bool secrets_encrypt_password(TALLOC_CTX *mem_ctx,
				     const char *plaintext,
				     DATA_BLOB *ciphertext)
{
	uint8_t key[32];
	uint8_t iv[16];
	gnutls_cipher_hd_t cipher_hnd = NULL;
	gnutls_datum_t key_datum;
	gnutls_datum_t iv_datum;
	int rc;
	size_t plaintext_len;
	size_t padded_len;
	uint8_t *padded_data = NULL;
	uint8_t padding;

	if (plaintext == NULL || ciphertext == NULL) {
		return false;
	}

	/* Get encryption key */
	if (!secrets_get_encryption_key(key)) {
		return false;
	}

	/* Generate random IV */
	generate_random_buffer(iv, sizeof(iv));

	plaintext_len = strlen(plaintext);
	/* PKCS#7 padding to 16-byte boundary */
	padding = 16 - (plaintext_len % 16);
	padded_len = plaintext_len + padding;

	padded_data = talloc_zero_array(mem_ctx, uint8_t, padded_len);
	if (padded_data == NULL) {
		ZERO_ARRAY(key);
		return false;
	}

	memcpy(padded_data, plaintext, plaintext_len);
	/* Apply PKCS#7 padding */
	memset(padded_data + plaintext_len, padding, padding);

	key_datum.data = key;
	key_datum.size = 32;
	iv_datum.data = iv;
	iv_datum.size = 16;

	rc = gnutls_cipher_init(&cipher_hnd,
				GNUTLS_CIPHER_AES_256_CBC,
				&key_datum,
				&iv_datum);
	ZERO_ARRAY(key);

	if (rc < 0) {
		DEBUG(0, ("gnutls_cipher_init failed: %s\n",
			  gnutls_strerror(rc)));
		BURN_FREE(padded_data, padded_len);
		return false;
	}

	rc = gnutls_cipher_encrypt(cipher_hnd, padded_data, padded_len);
	gnutls_cipher_deinit(cipher_hnd);

	if (rc < 0) {
		DEBUG(0, ("gnutls_cipher_encrypt failed: %s\n",
			  gnutls_strerror(rc)));
		BURN_FREE(padded_data, padded_len);
		return false;
	}

	/* Prepend IV to ciphertext */
	*ciphertext = data_blob_talloc(mem_ctx, NULL, 16 + padded_len);
	if (ciphertext->data == NULL) {
		BURN_FREE(padded_data, padded_len);
		return false;
	}

	memcpy(ciphertext->data, iv, 16);
	memcpy(ciphertext->data + 16, padded_data, padded_len);
	BURN_FREE(padded_data, padded_len);

	return true;
}

/*
 * Decrypt password data retrieved from storage
 */
static bool secrets_decrypt_password(TALLOC_CTX *mem_ctx,
				     const DATA_BLOB *ciphertext,
				     char **plaintext)
{
	uint8_t key[32];
	uint8_t iv[16];
	gnutls_cipher_hd_t cipher_hnd = NULL;
	gnutls_datum_t key_datum;
	gnutls_datum_t iv_datum;
	int rc;
	uint8_t *decrypted_data = NULL;
	size_t ciphertext_len;
	uint8_t padding;
	size_t plaintext_len;

	if (ciphertext == NULL || plaintext == NULL) {
		return false;
	}

	/* Need at least IV (16 bytes) + one block (16 bytes) */
	if (ciphertext->length < 32) {
		DEBUG(0, ("Ciphertext too short for decryption\n"));
		return false;
	}

	/* Get encryption key */
	if (!secrets_get_encryption_key(key)) {
		return false;
	}

	/* Extract IV from the beginning of ciphertext */
	memcpy(iv, ciphertext->data, 16);
	ciphertext_len = ciphertext->length - 16;

	decrypted_data = talloc_zero_array(mem_ctx, uint8_t, ciphertext_len + 1);
	if (decrypted_data == NULL) {
		ZERO_ARRAY(key);
		return false;
	}

	memcpy(decrypted_data, ciphertext->data + 16, ciphertext_len);

	key_datum.data = key;
	key_datum.size = 32;
	iv_datum.data = iv;
	iv_datum.size = 16;

	rc = gnutls_cipher_init(&cipher_hnd,
				GNUTLS_CIPHER_AES_256_CBC,
				&key_datum,
				&iv_datum);
	ZERO_ARRAY(key);

	if (rc < 0) {
		DEBUG(0, ("gnutls_cipher_init failed: %s\n",
			  gnutls_strerror(rc)));
		BURN_FREE(decrypted_data, ciphertext_len);
		return false;
	}

	rc = gnutls_cipher_decrypt(cipher_hnd, decrypted_data, ciphertext_len);
	gnutls_cipher_deinit(cipher_hnd);

	if (rc < 0) {
		DEBUG(0, ("gnutls_cipher_decrypt failed: %s\n",
			  gnutls_strerror(rc)));
		BURN_FREE(decrypted_data, ciphertext_len);
		return false;
	}

	/* Remove PKCS#7 padding */
	padding = decrypted_data[ciphertext_len - 1];
	if (padding == 0 || padding > 16 || padding > ciphertext_len) {
		DEBUG(0, ("Invalid padding in decrypted data\n"));
		BURN_FREE(decrypted_data, ciphertext_len);
		return false;
	}

	plaintext_len = ciphertext_len - padding;
	decrypted_data[plaintext_len] = '\0';

	*plaintext = (char *)decrypted_data;
	talloc_keep_secret(*plaintext);

	return true;
}

/* read a entry from the secrets database - the caller must free the result
   if size is non-null then the size of the entry is put in there
 */
void *secrets_fetch(const char *key, size_t *size)
{
	TDB_DATA dbuf;
	void *result;
	NTSTATUS status;

	if (!secrets_init()) {
		return NULL;
	}

	status = dbwrap_fetch(db_ctx, talloc_tos(), string_tdb_data(key),
			      &dbuf);
	if (!NT_STATUS_IS_OK(status)) {
		return NULL;
	}

	result = smb_memdup(dbuf.dptr, dbuf.dsize);
	if (result == NULL) {
		return NULL;
	}
	/*
	 * secrets_fetch() is a generic code and may be used for sensitive data,
	 * so clear the local dbuf.dptr memory via BURN_PTR_SIZE().
	 * The future plan is to convert secrets_fetch() to talloc.
	 * That would improve performance via:
	 * - avoid smb_memdup() above, instead directly return dbuf.dptr
	 * - BURN_PTR_SIZE() will be done not here but in the caller and only
	 *   if the caller asks for sensitive data.
	 */
	BURN_PTR_SIZE(dbuf.dptr, dbuf.dsize);
	TALLOC_FREE(dbuf.dptr);

	if (size) {
		*size = dbuf.dsize;
	}

	return result;
}

/* store a secrets entry
 */
bool secrets_store(const char *key, const void *data, size_t size)
{
	NTSTATUS status;

	if (!secrets_init()) {
		return false;
	}

	status = dbwrap_trans_store(db_ctx, string_tdb_data(key),
				    make_tdb_data((const uint8_t *)data, size),
				    TDB_REPLACE);
	return NT_STATUS_IS_OK(status);
}

bool secrets_store_creds(struct cli_credentials *creds)
{
	const char *p = NULL;
	bool ok;

	p = cli_credentials_get_username(creds);
	if (p == NULL) {
		return false;
	}

	ok = secrets_store(SECRETS_AUTH_USER, p, strlen(p) + 1);
	if (!ok) {
		DBG_ERR("Failed storing auth user name\n");
		return false;
	}


	p = cli_credentials_get_domain(creds);
	if (p == NULL) {
		return false;
	}

	ok = secrets_store(SECRETS_AUTH_DOMAIN, p, strlen(p) + 1);
	if (!ok) {
		DBG_ERR("Failed storing auth domain name\n");
		return false;
	}


	p = cli_credentials_get_password(creds);
	if (p == NULL) {
		return false;
	}

	ok = secrets_store(SECRETS_AUTH_PASSWORD, p, strlen(p) + 1);
	if (!ok) {
		DBG_ERR("Failed storing auth password\n");
		return false;
	}

	return true;
}


/* delete a secets database entry
 */
bool secrets_delete_entry(const char *key)
{
	NTSTATUS status;
	if (!secrets_init()) {
		return false;
	}

	status = dbwrap_trans_delete(db_ctx, string_tdb_data(key));

	return NT_STATUS_IS_OK(status);
}

/*
 * Deletes the key if it exists.
 */
bool secrets_delete(const char *key)
{
	bool exists;

	if (!secrets_init()) {
		return false;
	}

	exists = dbwrap_exists(db_ctx, string_tdb_data(key));
	if (!exists) {
		return true;
	}

	return secrets_delete_entry(key);
}

/**
 * Form a key for fetching a trusted domain password
 *
 * @param domain trusted domain name
 *
 * @return stored password's key
 **/
static char *trustdom_keystr(const char *domain)
{
	char *keystr;

	keystr = talloc_asprintf_strupper_m(talloc_tos(), "%s/%s",
					    SECRETS_DOMTRUST_ACCT_PASS,
					    domain);
	SMB_ASSERT(keystr != NULL);
	return keystr;
}

/************************************************************************
 Routine to get account password to trusted domain
************************************************************************/

bool secrets_fetch_trusted_domain_password(const char *domain, char** pwd,
                                           struct dom_sid *sid, time_t *pass_last_set_time)
{
	struct TRUSTED_DOM_PASS pass;
	enum ndr_err_code ndr_err;
	TALLOC_CTX *tmp_ctx = NULL;
	const char *stored_pass = NULL;
	char *decrypted_pass = NULL;

	/* unpacking structures */
	DATA_BLOB blob;

	/* fetching trusted domain password structure */
	if (!(blob.data = (uint8_t *)secrets_fetch(trustdom_keystr(domain),
						   &blob.length))) {
		DEBUG(5, ("secrets_fetch failed!\n"));
		return False;
	}

	tmp_ctx = talloc_new(NULL);
	if (tmp_ctx == NULL) {
		BURN_FREE(blob.data, blob.length);
		return false;
	}

	/* unpack trusted domain password */
	ndr_err = ndr_pull_struct_blob(&blob, tmp_ctx, &pass,
			(ndr_pull_flags_fn_t)ndr_pull_TRUSTED_DOM_PASS);

	/* This blob is NOT talloc based! */
	BURN_FREE(blob.data, blob.length);

	if (!NDR_ERR_CODE_IS_SUCCESS(ndr_err)) {
		talloc_free(tmp_ctx);
		return false;
	}

	stored_pass = pass.pass;
	if (stored_pass != NULL) {
		talloc_keep_secret(discard_const_p(char, stored_pass));
	}

	/* Check if password is encrypted */
	if (stored_pass != NULL && 
	    strncmp(stored_pass, ENCRYPTED_PASSWORD_PREFIX,
		    strlen(ENCRYPTED_PASSWORD_PREFIX)) == 0) {
		/* Password is encrypted, decrypt it */
		const char *encrypted_b64 = stored_pass + strlen(ENCRYPTED_PASSWORD_PREFIX);
		DATA_BLOB encrypted_blob;
		
		encrypted_blob = base64_decode_data_blob_talloc(tmp_ctx, encrypted_b64);
		if (encrypted_blob.data == NULL) {
			DEBUG(0, ("Failed to decode base64 encrypted password\n"));
			talloc_free(tmp_ctx);
			return false;
		}

		if (!secrets_decrypt_password(tmp_ctx, &encrypted_blob, &decrypted_pass)) {
			DEBUG(0, ("Failed to decrypt trusted domain password\n"));
			data_blob_clear_free(&encrypted_blob);
			talloc_free(tmp_ctx);
			return false;
		}
		data_blob_clear_free(&encrypted_blob);
		
		stored_pass = decrypted_pass;
		talloc_keep_secret(decrypted_pass);
	}

	/* the trust's password */
	if (pwd) {
		*pwd = SMB_STRDUP(stored_pass);
		if (!*pwd) {
			talloc_free(tmp_ctx);
			return False;
		}
		talloc_keep_secret(*pwd);
	}

	/* last change time */
	if (pass_last_set_time) *pass_last_set_time = pass.mod_time;

	/* domain sid */
	if (sid != NULL) sid_copy(sid, &pass.domain_sid);

	talloc_free(tmp_ctx);
	return True;
}

/**
 * Routine to store the password for trusted domain
 *
 * @param domain remote domain name
 * @param pwd plain text password of trust relationship
 * @param sid remote domain sid
 *
 * @return true if succeeded
 **/

bool secrets_store_trusted_domain_password(const char* domain, const char* pwd,
                                           const struct dom_sid *sid)
{
	bool ret;
	TALLOC_CTX *tmp_ctx = NULL;

	/* packing structures */
	DATA_BLOB blob;
	DATA_BLOB encrypted_pwd;
	enum ndr_err_code ndr_err;
	struct TRUSTED_DOM_PASS pass;
	char *encrypted_pwd_b64 = NULL;
	char *encrypted_pwd_str = NULL;
	ZERO_STRUCT(pass);
	ZERO_STRUCT(encrypted_pwd);

	tmp_ctx = talloc_new(NULL);
	if (tmp_ctx == NULL) {
		return false;
	}

	/* Encrypt the password before storing */
	if (!secrets_encrypt_password(tmp_ctx, pwd, &encrypted_pwd)) {
		DEBUG(0, ("Failed to encrypt trusted domain password\n"));
		talloc_free(tmp_ctx);
		return false;
	}

	/* Encode encrypted password as base64 */
	encrypted_pwd_b64 = base64_encode_data_blob(tmp_ctx, encrypted_pwd);
	data_blob_clear_free(&encrypted_pwd);
	
	if (encrypted_pwd_b64 == NULL) {
		DEBUG(0, ("Failed to base64 encode encrypted password\n"));
		talloc_free(tmp_ctx);
		return false;
	}

	/* Prefix with marker to indicate encryption */
	encrypted_pwd_str = talloc_asprintf(tmp_ctx, "%s%s",
					    ENCRYPTED_PASSWORD_PREFIX,
					    encrypted_pwd_b64);
	BURN_FREE_STR(encrypted_pwd_b64);
	
	if (encrypted_pwd_str == NULL) {
		talloc_free(tmp_ctx);
		return false;
	}

	pass.uni_name = domain;
	pass.uni_name_len = strlen(domain)+1;

	/* last change time */
	pass.mod_time = time(NULL);

	/* Store encrypted password */
	pass.pass_len = strlen(encrypted_pwd_str);
	pass.pass = encrypted_pwd_str;

	/* domain sid */
	sid_copy(&pass.domain_sid, sid);

	ndr_err = ndr_push_struct_blob(&blob, tmp_ctx, &pass,
			(ndr_push_flags_fn_t)ndr_push_TRUSTED_DOM_PASS);

	if (!NDR_ERR_CODE_IS_SUCCESS(ndr_err)) {
		talloc_free(tmp_ctx);
		return false;
	}

	ret = secrets_store(trustdom_keystr(domain), blob.data, blob.length);

	/* This blob is talloc based. */
	data_blob_clear_free(&blob);
	talloc_free(tmp_ctx);

	return ret;
}

/************************************************************************
 Routine to delete the password for trusted domain
************************************************************************/

bool trusted_domain_password_delete(const char *domain)
{
	return secrets_delete_entry(trustdom_keystr(domain));
}

bool secrets_store_ldap_pw(const char* dn, char* pw)
{
	char *key = NULL;
	bool ret;
	TALLOC_CTX *tmp_ctx = NULL;
	DATA_BLOB encrypted_pwd;
	char *encrypted_pwd_b64 = NULL;
	char *encrypted_pwd_str = NULL;

	if (asprintf(&key, "%s/%s", SECRETS_LDAP_BIND_PW, dn) < 0) {
		DEBUG(0, ("secrets_store_ldap_pw: asprintf failed!\n"));
		return False;
	}

	tmp_ctx = talloc_new(NULL);
	if (tmp_ctx == NULL) {
		SAFE_FREE(key);
		return false;
	}

	/* Encrypt the password before storing */
	if (!secrets_encrypt_password(tmp_ctx, pw, &encrypted_pwd)) {
		DEBUG(0, ("Failed to encrypt LDAP password\n"));
		SAFE_FREE(key);
		talloc_free(tmp_ctx);
		return false;
	}

	/* Encode encrypted password as base64 */
	encrypted_pwd_b64 = base64_encode_data_blob(tmp_ctx, encrypted_pwd);
	data_blob_clear_free(&encrypted_pwd);
	
	if (encrypted_pwd_b64 == NULL) {
		DEBUG(0, ("Failed to base64 encode encrypted LDAP password\n"));
		SAFE_FREE(key);
		talloc_free(tmp_ctx);
		return false;
	}

	/* Prefix with marker to indicate encryption */
	encrypted_pwd_str = talloc_asprintf(tmp_ctx, "%s%s",
					    ENCRYPTED_PASSWORD_PREFIX,
					    encrypted_pwd_b64);
	BURN_FREE_STR(encrypted_pwd_b64);
	
	if (encrypted_pwd_str == NULL) {
		SAFE_FREE(key);
		talloc_free(tmp_ctx);
		return false;
	}

	ret = secrets_store(key, encrypted_pwd_str, strlen(encrypted_pwd_str)+1);

	SAFE_FREE(key);
	talloc_free(tmp_ctx);
	return ret;
}

/*******************************************************************
 Find the ldap password.
******************************************************************/

bool fetch_ldap_pw(char **dn, char** pw)
{
	char *key = NULL;
	size_t size = 0;
	char *stored_pw = NULL;
	TALLOC_CTX *tmp_ctx = NULL;

	*dn = smb_xstrdup(lp_ldap_admin_dn());

	if (asprintf(&key, "%s/%s", SECRETS_LDAP_BIND_PW, *dn) < 0) {
		SAFE_FREE(*dn);
		DEBUG(0, ("fetch_ldap_pw: asprintf failed!\n"));
		return false;
	}

	stored_pw = (char *)secrets_fetch(key, &size);
	SAFE_FREE(key);

	if (stored_pw == NULL || size == 0 || stored_pw[size-1] != '\0') {
		DBG_ERR("No valid password for %s\n", *dn);
		BURN_FREE_STR(stored_pw);
		SAFE_FREE(*dn);
		return false;
	}

	/* Check if password is encrypted */
	if (strncmp(stored_pw, ENCRYPTED_PASSWORD_PREFIX,
		    strlen(ENCRYPTED_PASSWORD_PREFIX)) == 0) {
		/* Password is encrypted, decrypt it */
		const char *encrypted_b64 = stored_pw + strlen(ENCRYPTED_PASSWORD_PREFIX);
		DATA_BLOB encrypted_blob;
		char *decrypted_pw = NULL;

		tmp_ctx = talloc_new(NULL);
		if (tmp_ctx == NULL) {
			BURN_FREE_STR(stored_pw);
			SAFE_FREE(*dn);
			return false;
		}

		encrypted_blob = base64_decode_data_blob_talloc(tmp_ctx, encrypted_b64);
		BURN_FREE_STR(stored_pw);
		
		if (encrypted_blob.data == NULL) {
			DEBUG(0, ("Failed to decode base64 encrypted LDAP password\n"));
			talloc_free(tmp_ctx);
			SAFE_FREE(*dn);
			return false;
		}

		if (!secrets_decrypt_password(tmp_ctx, &encrypted_blob, &decrypted_pw)) {
			DEBUG(0, ("Failed to decrypt LDAP password\n"));
			data_blob_clear_free(&encrypted_blob);
			talloc_free(tmp_ctx);
			SAFE_FREE(*dn);
			return false;
		}
		data_blob_clear_free(&encrypted_blob);

		*pw = smb_xstrdup(decrypted_pw);
		talloc_free(tmp_ctx);
	} else {
		/* Legacy plaintext password */
		*pw = stored_pw;
	}

	if (*pw == NULL) {
		SAFE_FREE(*dn);
		return false;
	}

	return true;
}

/*******************************************************************************
 Store a complete AFS keyfile into secrets.tdb.
*******************************************************************************/

bool secrets_store_afs_keyfile(const char *cell, const struct afs_keyfile *keyfile)
{
	fstring key;

	if ((cell == NULL) || (keyfile == NULL))
		return False;

	if (ntohl(keyfile->nkeys) > SECRETS_AFS_MAXKEYS)
		return False;

	slprintf(key, sizeof(key)-1, "%s/%s", SECRETS_AFS_KEYFILE, cell);
	return secrets_store(key, keyfile, sizeof(struct afs_keyfile));
}

/*******************************************************************************
 Fetch the current (highest) AFS key from secrets.tdb
*******************************************************************************/
bool secrets_fetch_afs_key(const char *cell, struct afs_key *result)
{
	fstring key;
	struct afs_keyfile *keyfile;
	size_t size = 0;
	uint32_t i;

	slprintf(key, sizeof(key)-1, "%s/%s", SECRETS_AFS_KEYFILE, cell);

	keyfile = (struct afs_keyfile *)secrets_fetch(key, &size);

	if (keyfile == NULL)
		return False;

	if (size != sizeof(struct afs_keyfile)) {
		BURN_FREE(keyfile, sizeof(*keyfile));
		return False;
	}

	i = ntohl(keyfile->nkeys);

	if (i > SECRETS_AFS_MAXKEYS) {
		BURN_FREE(keyfile, sizeof(*keyfile));
		return False;
	}

	*result = keyfile->entry[i-1];

	result->kvno = ntohl(result->kvno);

	BURN_FREE(keyfile, sizeof(*keyfile));

	return True;
}

/******************************************************************************
  When kerberos is not available, choose between anonymous or
  authenticated connections.

  We need to use an authenticated connection if DCs have the
  RestrictAnonymous registry entry set > 0, or the "Additional
  restrictions for anonymous connections" set in the win2k Local
  Security Policy.

  Caller to free() result in domain, username using SAFE_FREE() and password using BURN_FREE_STR()
*******************************************************************************/
void secrets_fetch_ipc_userpass(char **username, char **domain, char **password)
{
	size_t username_size, domain_size, password_size;
	char *raw_username, *raw_domain, *raw_password;
	
	/* Fetch raw data from secrets database */
	raw_username = (char *)secrets_fetch(SECRETS_AUTH_USER, &username_size);
	raw_domain = (char *)secrets_fetch(SECRETS_AUTH_DOMAIN, &domain_size);
	raw_password = (char *)secrets_fetch(SECRETS_AUTH_PASSWORD, &password_size);
	
	/* Ensure null-termination for string safety */
	if (raw_username != NULL) {
		*username = malloc(username_size + 1);
		if (*username != NULL) {
			memcpy(*username, raw_username, username_size);
			(*username)[username_size] = '\0';
		}
		BURN_FREE(raw_username, username_size);
	} else {
		*username = NULL;
	}
	
	if (raw_domain != NULL) {
		*domain = malloc(domain_size + 1);
		if (*domain != NULL) {
			memcpy(*domain, raw_domain, domain_size);
			(*domain)[domain_size] = '\0';
		}
		BURN_FREE(raw_domain, domain_size);
	} else {
		*domain = NULL;
	}
	
	if (raw_password != NULL) {
		*password = malloc(password_size + 1);
		if (*password != NULL) {
			memcpy(*password, raw_password, password_size);
			(*password)[password_size] = '\0';
		}
		BURN_FREE(raw_password, password_size);
	} else {
		*password = NULL;
	}

	if (*username && **username) {

		if (!*domain || !**domain) {
			SAFE_FREE(*domain);
			*domain = smb_xstrdup(lp_workgroup());
		}

		if (!*password || !**password) {
			BURN_FREE_STR(*password);
			*password = smb_xstrdup("");
		}

		DEBUG(3, ("IPC$ connections done by user %s\\%s\n",
			  *domain, *username));

	} else {
		DEBUG(3, ("IPC$ connections done anonymously\n"));
		SAFE_FREE(*username);
		SAFE_FREE(*domain);
		BURN_FREE_STR(*password);
		*username = smb_xstrdup("");
		*domain = smb_xstrdup("");
		*password = smb_xstrdup("");
	}
}

bool secrets_store_generic(const char *owner, const char *key, const char *secret)
{
	char *tdbkey = NULL;
	bool ret;

	if (asprintf(&tdbkey, "SECRETS/GENERIC/%s/%s", owner, key) < 0) {
		DEBUG(0, ("asprintf failed!\n"));
		return False;
	}

	ret = secrets_store(tdbkey, secret, strlen(secret)+1);

	SAFE_FREE(tdbkey);
	return ret;
}

/*******************************************************************
 Find the ldap password.
******************************************************************/

char *secrets_fetch_generic(const char *owner, const char *key)
{
	char *secret = NULL;
	char *tdbkey = NULL;

	if (( ! owner) || ( ! key)) {
		DEBUG(1, ("Invalid Parameters\n"));
		return NULL;
	}

	if (asprintf(&tdbkey, "SECRETS/GENERIC/%s/%s", owner, key) < 0) {
		DEBUG(0, ("Out of memory!\n"));
		return NULL;
	}

	secret = (char *)secrets_fetch(tdbkey, NULL);
	SAFE_FREE(tdbkey);

	return secret;
}


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
#include <gnutls/gnutls.h>
#include <gnutls/crypto.h>
#include "lib/crypto/gnutls_helpers.h"

#undef DBGC_CLASS
#define DBGC_CLASS DBGC_PASSDB

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

/*
 * Derive a 256-bit encryption key for trusted domain password protection.
 * Uses system-specific data to ensure the key is unique per installation.
 * The key is derived from: local machine SID + domain name + version string
 */
static bool derive_trustdom_encryption_key(TALLOC_CTX *mem_ctx,
					   const char *domain,
					   uint8_t key_out[32])
{
	DATA_BLOB domain_blob = data_blob_string_const(domain);
	DATA_BLOB context_blob = data_blob_string_const("SAMBA_TRUSTDOM_KEY_V1");
	struct dom_sid local_sid;
	char *sid_str = NULL;
	DATA_BLOB sid_blob = {0};
	uint8_t *combined = NULL;
	size_t combined_len;
	gnutls_hash_hd_t hash_hnd = NULL;
	int rc;
	bool ok;

	/* Get local machine SID for additional entropy */
	ok = secrets_fetch_domain_sid(lp_netbios_name(), &local_sid);
	if (ok) {
		sid_str = dom_sid_string(mem_ctx, &local_sid);
		if (sid_str != NULL) {
			sid_blob = data_blob_string_const(sid_str);
		}
	}

	/* Combine local SID, domain name, and context for key derivation */
	combined_len = sid_blob.length + domain_blob.length + context_blob.length;
	combined = talloc_array(mem_ctx, uint8_t, combined_len);
	if (combined == NULL) {
		TALLOC_FREE(sid_str);
		return false;
	}

	if (sid_blob.length > 0) {
		memcpy(combined, sid_blob.data, sid_blob.length);
	}
	memcpy(combined + sid_blob.length, domain_blob.data, domain_blob.length);
	memcpy(combined + sid_blob.length + domain_blob.length,
	       context_blob.data, context_blob.length);

	TALLOC_FREE(sid_str);

	/* Derive key using SHA-256 */
	rc = gnutls_hash_init(&hash_hnd, GNUTLS_DIG_SHA256);
	if (rc < 0) {
		TALLOC_FREE(combined);
		return false;
	}

	rc = gnutls_hash(hash_hnd, combined, combined_len);
	if (rc < 0) {
		gnutls_hash_deinit(hash_hnd, NULL);
		TALLOC_FREE(combined);
		return false;
	}

	gnutls_hash_deinit(hash_hnd, key_out);
	BURN_PTR_SIZE(combined, combined_len);
	TALLOC_FREE(combined);

	return true;
}

/*
 * Encrypt a trusted domain password using AES-256-GCM
 */
static bool encrypt_trustdom_password(TALLOC_CTX *mem_ctx,
				      const char *domain,
				      const char *plaintext_pwd,
				      DATA_BLOB *encrypted_blob)
{
	uint8_t key[32];
	uint8_t iv[16];
	uint8_t tag[16];
	gnutls_cipher_hd_t cipher_hnd = NULL;
	gnutls_datum_t key_datum;
	gnutls_datum_t iv_datum;
	size_t pwd_len;
	uint8_t *ciphertext = NULL;
	uint8_t *result = NULL;
	int rc;
	bool ok;

	if (plaintext_pwd == NULL) {
		return false;
	}

	pwd_len = strlen(plaintext_pwd);
	if (pwd_len == 0) {
		return false;
	}

	/* Derive encryption key */
	ok = derive_trustdom_encryption_key(mem_ctx, domain, key);
	if (!ok) {
		return false;
	}

	/* Generate random IV */
	generate_random_buffer(iv, sizeof(iv));

	/* Allocate ciphertext buffer */
	ciphertext = talloc_array(mem_ctx, uint8_t, pwd_len);
	if (ciphertext == NULL) {
		BURN_PTR_SIZE(key, sizeof(key));
		return false;
	}
	memcpy(ciphertext, plaintext_pwd, pwd_len);

	/* Initialize cipher */
	key_datum.data = key;
	key_datum.size = sizeof(key);
	iv_datum.data = iv;
	iv_datum.size = sizeof(iv);

	rc = gnutls_cipher_init(&cipher_hnd, GNUTLS_CIPHER_AES_256_GCM,
				&key_datum, &iv_datum);
	if (rc < 0) {
		BURN_PTR_SIZE(key, sizeof(key));
		BURN_PTR_SIZE(ciphertext, pwd_len);
		TALLOC_FREE(ciphertext);
		return false;
	}

	/* Encrypt */
	rc = gnutls_cipher_encrypt(cipher_hnd, ciphertext, pwd_len);
	if (rc < 0) {
		gnutls_cipher_deinit(cipher_hnd);
		BURN_PTR_SIZE(key, sizeof(key));
		BURN_PTR_SIZE(ciphertext, pwd_len);
		TALLOC_FREE(ciphertext);
		return false;
	}

	/* Get authentication tag */
	rc = gnutls_cipher_tag(cipher_hnd, tag, sizeof(tag));
	gnutls_cipher_deinit(cipher_hnd);
	
	if (rc < 0) {
		BURN_PTR_SIZE(key, sizeof(key));
		BURN_PTR_SIZE(ciphertext, pwd_len);
		TALLOC_FREE(ciphertext);
		return false;
	}

	BURN_PTR_SIZE(key, sizeof(key));

	/* Build result: IV (16) + tag (16) + ciphertext */
	result = talloc_array(mem_ctx, uint8_t, 16 + 16 + pwd_len);
	if (result == NULL) {
		BURN_PTR_SIZE(ciphertext, pwd_len);
		TALLOC_FREE(ciphertext);
		return false;
	}

	memcpy(result, iv, 16);
	memcpy(result + 16, tag, 16);
	memcpy(result + 32, ciphertext, pwd_len);

	BURN_PTR_SIZE(ciphertext, pwd_len);
	TALLOC_FREE(ciphertext);

	*encrypted_blob = data_blob_talloc(mem_ctx, result, 32 + pwd_len);
	TALLOC_FREE(result);

	return (encrypted_blob->data != NULL);
}

/*
 * Decrypt a trusted domain password using AES-256-GCM
 */
static bool decrypt_trustdom_password(TALLOC_CTX *mem_ctx,
				      const char *domain,
				      const DATA_BLOB *encrypted_blob,
				      char **plaintext_pwd)
{
	uint8_t key[32];
	uint8_t iv[16];
	uint8_t tag[16];
	gnutls_cipher_hd_t cipher_hnd = NULL;
	gnutls_datum_t key_datum;
	gnutls_datum_t iv_datum;
	size_t ciphertext_len;
	uint8_t *plaintext = NULL;
	char *result = NULL;
	int rc;
	bool ok;

	/* Encrypted blob must be at least IV(16) + tag(16) */
	if (encrypted_blob == NULL || encrypted_blob->length < 32) {
		return false;
	}

	ciphertext_len = encrypted_blob->length - 32;

	/* Extract IV and tag */
	memcpy(iv, encrypted_blob->data, 16);
	memcpy(tag, encrypted_blob->data + 16, 16);

	/* Derive decryption key */
	ok = derive_trustdom_encryption_key(mem_ctx, domain, key);
	if (!ok) {
		return false;
	}

	/* Allocate plaintext buffer */
	plaintext = talloc_array(mem_ctx, uint8_t, ciphertext_len + 1);
	if (plaintext == NULL) {
		BURN_PTR_SIZE(key, sizeof(key));
		return false;
	}
	memcpy(plaintext, encrypted_blob->data + 32, ciphertext_len);

	/* Initialize cipher */
	key_datum.data = key;
	key_datum.size = sizeof(key);
	iv_datum.data = iv;
	iv_datum.size = sizeof(iv);

	rc = gnutls_cipher_init(&cipher_hnd, GNUTLS_CIPHER_AES_256_GCM,
				&key_datum, &iv_datum);
	if (rc < 0) {
		BURN_PTR_SIZE(key, sizeof(key));
		BURN_PTR_SIZE(plaintext, ciphertext_len);
		TALLOC_FREE(plaintext);
		return false;
	}

	/* Set and verify authentication tag */
	rc = gnutls_cipher_tag(cipher_hnd, tag, sizeof(tag));
	if (rc < 0) {
		gnutls_cipher_deinit(cipher_hnd);
		BURN_PTR_SIZE(key, sizeof(key));
		BURN_PTR_SIZE(plaintext, ciphertext_len);
		TALLOC_FREE(plaintext);
		return false;
	}

	/* Decrypt */
	rc = gnutls_cipher_decrypt(cipher_hnd, plaintext, ciphertext_len);
	gnutls_cipher_deinit(cipher_hnd);
	BURN_PTR_SIZE(key, sizeof(key));

	if (rc < 0) {
		BURN_PTR_SIZE(plaintext, ciphertext_len);
		TALLOC_FREE(plaintext);
		return false;
	}

	/* Null-terminate and return */
	plaintext[ciphertext_len] = '\0';
	result = talloc_strdup(mem_ctx, (char *)plaintext);
	BURN_PTR_SIZE(plaintext, ciphertext_len);
	TALLOC_FREE(plaintext);

	if (result == NULL) {
		return false;
	}

	talloc_keep_secret(result);
	*plaintext_pwd = result;
	return true;
}

/************************************************************************
 Routine to get account password to trusted domain
************************************************************************/

bool secrets_fetch_trusted_domain_password(const char *domain, char** pwd,
                                           struct dom_sid *sid, time_t *pass_last_set_time)
{
	struct TRUSTED_DOM_PASS pass;
	enum ndr_err_code ndr_err;
	DATA_BLOB blob;
	char *decrypted_pwd = NULL;
	bool is_encrypted = false;

	/* fetching trusted domain password structure */
	if (!(blob.data = (uint8_t *)secrets_fetch(trustdom_keystr(domain),
						   &blob.length))) {
		DEBUG(5, ("secrets_fetch failed!\n"));
		return False;
	}

	/* unpack trusted domain password */
	ndr_err = ndr_pull_struct_blob(&blob, talloc_tos(), &pass,
			(ndr_pull_flags_fn_t)ndr_pull_TRUSTED_DOM_PASS);

	/* This blob is NOT talloc based! */
	BURN_FREE(blob.data, blob.length);

	if (!NDR_ERR_CODE_IS_SUCCESS(ndr_err)) {
		return false;
	}

	if (pass.pass != NULL) {
		talloc_keep_secret(discard_const_p(char, pass.pass));
	}

	/* Check if password is encrypted (starts with magic marker) */
	if (pass.pass != NULL && pass.pass_len >= 32 &&
	    strncmp(pass.pass, "ENCRYPTED:", 10) == 0) {
		DATA_BLOB encrypted_data;
		bool ok;

		is_encrypted = true;
		/* Skip the "ENCRYPTED:" prefix */
		encrypted_data.data = (uint8_t *)(pass.pass + 10);
		encrypted_data.length = pass.pass_len - 10;

		ok = decrypt_trustdom_password(talloc_tos(), domain,
					       &encrypted_data,
					       &decrypted_pwd);
		if (!ok) {
			DEBUG(0, ("Failed to decrypt trusted domain password for %s\n",
				  domain));
			return false;
		}
	}

	/* the trust's password */
	if (pwd) {
		if (is_encrypted) {
			*pwd = SMB_STRDUP(decrypted_pwd);
			BURN_STR(decrypted_pwd);
			TALLOC_FREE(decrypted_pwd);
		} else {
			*pwd = SMB_STRDUP(pass.pass);
		}
		if (!*pwd) {
			return False;
		}
		talloc_keep_secret(*pwd);
	} else if (is_encrypted) {
		BURN_STR(decrypted_pwd);
		TALLOC_FREE(decrypted_pwd);
	}

	/* last change time */
	if (pass_last_set_time) *pass_last_set_time = pass.mod_time;

	/* domain sid */
	if (sid != NULL) sid_copy(sid, &pass.domain_sid);

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
	DATA_BLOB blob;
	DATA_BLOB encrypted_pwd;
	enum ndr_err_code ndr_err;
	struct TRUSTED_DOM_PASS pass;
	char *encrypted_pwd_str = NULL;
	bool ok;
	TALLOC_CTX *tmp_ctx = talloc_tos();

	ZERO_STRUCT(pass);

	/* Encrypt the password */
	ok = encrypt_trustdom_password(tmp_ctx, domain, pwd, &encrypted_pwd);
	if (!ok) {
		DEBUG(0, ("Failed to encrypt trusted domain password for %s\n",
			  domain));
		return false;
	}

	/* Prepare encrypted password string with magic marker */
	encrypted_pwd_str = talloc_asprintf(tmp_ctx, "ENCRYPTED:%*s",
					    (int)encrypted_pwd.length,
					    "");
	if (encrypted_pwd_str == NULL) {
		data_blob_clear_free(&encrypted_pwd);
		return false;
	}
	
	/* Copy encrypted data after the prefix */
	memcpy(encrypted_pwd_str + 10, encrypted_pwd.data, encrypted_pwd.length);

	pass.uni_name = domain;
	pass.uni_name_len = strlen(domain)+1;

	/* last change time */
	pass.mod_time = time(NULL);

	/* encrypted password of the trust */
	pass.pass_len = 10 + encrypted_pwd.length;
	pass.pass = encrypted_pwd_str;

	/* domain sid */
	sid_copy(&pass.domain_sid, sid);

	ndr_err = ndr_push_struct_blob(&blob, tmp_ctx, &pass,
			(ndr_push_flags_fn_t)ndr_push_TRUSTED_DOM_PASS);
	
	/* Clear encrypted password from memory */
	data_blob_clear_free(&encrypted_pwd);
	BURN_STR(encrypted_pwd_str);

	if (!NDR_ERR_CODE_IS_SUCCESS(ndr_err)) {
		return false;
	}

	ret = secrets_store(trustdom_keystr(domain), blob.data, blob.length);

	/* This blob is talloc based. */
	data_blob_clear_free(&blob);

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

	if (asprintf(&key, "%s/%s", SECRETS_LDAP_BIND_PW, dn) < 0) {
		DEBUG(0, ("secrets_store_ldap_pw: asprintf failed!\n"));
		return False;
	}

	ret = secrets_store(key, pw, strlen(pw)+1);

	SAFE_FREE(key);
	return ret;
}

/*******************************************************************
 Find the ldap password.
******************************************************************/

bool fetch_ldap_pw(char **dn, char** pw)
{
	char *key = NULL;
	size_t size = 0;

	*dn = smb_xstrdup(lp_ldap_admin_dn());

	if (asprintf(&key, "%s/%s", SECRETS_LDAP_BIND_PW, *dn) < 0) {
		SAFE_FREE(*dn);
		DEBUG(0, ("fetch_ldap_pw: asprintf failed!\n"));
		return false;
	}

	*pw=(char *)secrets_fetch(key, &size);
	SAFE_FREE(key);

	if (*pw == NULL || size == 0 || (*pw)[size-1] != '\0') {
		DBG_ERR("No valid password for %s\n", *dn);
		BURN_FREE_STR(*pw);
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


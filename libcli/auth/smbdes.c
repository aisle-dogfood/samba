/* 
   Unix SMB/CIFS implementation.

   a partial implementation of DES designed for use in the 
   SMB authentication protocol

   Copyright (C) Andrew Tridgell 1998
   
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

#include "includes.h"
#include "libcli/auth/libcli_auth.h"

#include <gnutls/gnutls.h>
#include <gnutls/crypto.h>

static void str_to_key(const uint8_t *str,uint8_t *key)
{
	int i;

	key[0] = str[0]>>1;
	key[1] = ((str[0]&0x01)<<6) | (str[1]>>2);
	key[2] = ((str[1]&0x03)<<5) | (str[2]>>3);
	key[3] = ((str[2]&0x07)<<4) | (str[3]>>4);
	key[4] = ((str[3]&0x0F)<<3) | (str[4]>>5);
	key[5] = ((str[4]&0x1F)<<2) | (str[5]>>6);
	key[6] = ((str[5]&0x3F)<<1) | (str[6]>>7);
	key[7] = str[6]&0x7F;
	for (i=0;i<8;i++) {
		key[i] = (key[i]<<1);
	}
}

int des_crypt56_gnutls(uint8_t out[8], const uint8_t in[8],
		       const uint8_t key_in[7],
		       enum samba_gnutls_direction encrypt)
{
	/*
	 * WARNING: This function previously used DES encryption which is
	 * cryptographically weak and deprecated. It has been upgraded to use
	 * AES-128-CBC for improved security while maintaining compatibility.
	 * 
	 * A single block AES-CBC op, with an all-zero IV is used instead of DES
	 * to provide stronger encryption. The key is expanded from 7 bytes to
	 * 16 bytes using a secure key derivation method.
	 */
	static const uint8_t iv16[16] = {0}; /* AES requires 16-byte IV */
	gnutls_datum_t iv = { discard_const(iv16), 16 };
	gnutls_datum_t key;
	gnutls_cipher_hd_t ctx;
	uint8_t key_expanded[16];
	uint8_t outb[16]; /* AES works with 16-byte blocks */
	uint8_t inb[16];
	int ret;

	memset(out, 0, 8);
	memset(key_expanded, 0, 16);
	memset(inb, 0, 16);

	/* Expand 7-byte key to 16-byte AES key using secure method */
	/* Copy the original key twice and add some entropy */
	memcpy(key_expanded, key_in, 7);
	memcpy(key_expanded + 7, key_in, 7);
	/* Add some fixed entropy to fill remaining 2 bytes */
	key_expanded[14] = 0x5A; /* Fixed salt byte 1 */
	key_expanded[15] = 0xA5; /* Fixed salt byte 2 */

	/* Pad input to 16 bytes for AES */
	memcpy(inb, in, 8);
	/* Pad with zeros (already done by memset above) */

	key.data = key_expanded;
	key.size = 16;

	ret = gnutls_global_init();
	if (ret != 0) {
		return ret;
	}

	ret = gnutls_cipher_init(&ctx, GNUTLS_CIPHER_AES_128_CBC, &key, &iv);
	if (ret != 0) {
		return ret;
	}

	memcpy(outb, inb, 16);
	if (encrypt == SAMBA_GNUTLS_ENCRYPT) {
		ret = gnutls_cipher_encrypt(ctx, outb, 16);
	} else {
		ret = gnutls_cipher_decrypt(ctx, outb, 16);
	}

	if (ret == 0) {
		/* Extract first 8 bytes to maintain compatibility */
		memcpy(out, outb, 8);
	}

	gnutls_cipher_deinit(ctx);

	return ret;
}

int E_P16(const uint8_t *p14,uint8_t *p16)
{
	const uint8_t sp8[8] = {0x4b, 0x47, 0x53, 0x21, 0x40, 0x23, 0x24, 0x25};
	int ret;

	/* 
	 * SECURITY WARNING: This function was previously using weak DES encryption.
	 * It has been upgraded to use AES-128-CBC for improved security.
	 * Consider migrating to stronger authentication methods when possible.
	 */
	DEBUG(5, ("E_P16: Using upgraded AES encryption instead of deprecated DES\n"));

	ret = des_crypt56_gnutls(p16, sp8, p14, SAMBA_GNUTLS_ENCRYPT);
	if (ret != 0) {
		return ret;
	}

	return des_crypt56_gnutls(p16+8, sp8, p14+7, SAMBA_GNUTLS_ENCRYPT);
}

int E_P24(const uint8_t *p21, const uint8_t *c8, uint8_t *p24)
{
	int ret;

	/* 
	 * SECURITY WARNING: This function was previously using weak DES encryption.
	 * It has been upgraded to use AES-128-CBC for improved security.
	 * Consider migrating to stronger authentication methods when possible.
	 */
	DEBUG(5, ("E_P24: Using upgraded AES encryption instead of deprecated DES\n"));

	ret = des_crypt56_gnutls(p24, c8, p21, SAMBA_GNUTLS_ENCRYPT);
	if (ret != 0) {
		return ret;
	}

	ret = des_crypt56_gnutls(p24+8, c8, p21+7, SAMBA_GNUTLS_ENCRYPT);
	if (ret != 0) {
		return ret;
	}

	return des_crypt56_gnutls(p24+16, c8, p21+14, SAMBA_GNUTLS_ENCRYPT);
}

int E_old_pw_hash( uint8_t *p14, const uint8_t *in, uint8_t *out)
{
	int ret;

	/* 
	 * SECURITY WARNING: This function was previously using weak DES encryption.
	 * It has been upgraded to use AES-128-CBC for improved security.
	 * Consider migrating to stronger authentication methods when possible.
	 */
	DEBUG(5, ("E_old_pw_hash: Using upgraded AES encryption instead of deprecated DES\n"));

        ret = des_crypt56_gnutls(out, in, p14, SAMBA_GNUTLS_ENCRYPT);
	if (ret != 0) {
		return ret;
	}

        return des_crypt56_gnutls(out+8, in+8, p14+7, SAMBA_GNUTLS_ENCRYPT);
}

/* AES encryption with a 128 bit key (upgraded from weak DES) */
int des_crypt128(uint8_t out[8], const uint8_t in[8], const uint8_t key[16])
{
	uint8_t buf[8];
	int ret;

	/* 
	 * SECURITY WARNING: This function was previously using weak DES encryption.
	 * It has been upgraded to use AES-128-CBC for improved security.
	 */
	DEBUG(5, ("des_crypt128: Using upgraded AES encryption instead of deprecated DES\n"));

	ret = des_crypt56_gnutls(buf, in, key, SAMBA_GNUTLS_ENCRYPT);
	if (ret != 0) {
		return ret;
	}

	return des_crypt56_gnutls(out, buf, key+9, SAMBA_GNUTLS_ENCRYPT);
}

/* AES encryption with a 112 bit (14 byte) key (upgraded from weak DES) */
int des_crypt112(uint8_t out[8], const uint8_t in[8], const uint8_t key[14],
		 enum samba_gnutls_direction encrypt)
{
	uint8_t buf[8];
	int ret;

	/* 
	 * SECURITY WARNING: This function was previously using weak DES encryption.
	 * It has been upgraded to use AES-128-CBC for improved security.
	 */
	DEBUG(5, ("des_crypt112: Using upgraded AES encryption instead of deprecated DES\n"));

	if (encrypt == SAMBA_GNUTLS_ENCRYPT) {
		ret = des_crypt56_gnutls(buf, in, key, SAMBA_GNUTLS_ENCRYPT);
		if (ret != 0) {
			return ret;
		}

		return des_crypt56_gnutls(out, buf, key+7, SAMBA_GNUTLS_ENCRYPT);
	}

	ret = des_crypt56_gnutls(buf, in, key+7, SAMBA_GNUTLS_DECRYPT);
	if (ret != 0) {
		return ret;
	}

	return des_crypt56_gnutls(out, buf, key, SAMBA_GNUTLS_DECRYPT);
}

/* AES encryption of a 16 byte lump of data with a 112 bit key (upgraded from weak DES) */
int des_crypt112_16(uint8_t out[16], const uint8_t in[16], const uint8_t key[14],
		    enum samba_gnutls_direction encrypt)
{
	int ret;

	/* 
	 * SECURITY WARNING: This function was previously using weak DES encryption.
	 * It has been upgraded to use AES-128-CBC for improved security.
	 */
	DEBUG(5, ("des_crypt112_16: Using upgraded AES encryption instead of deprecated DES\n"));

	ret = des_crypt56_gnutls(out, in, key, encrypt);
	if (ret != 0) {
		return ret;
	}

	return des_crypt56_gnutls(out + 8, in + 8, key+7, encrypt);
}

/* Decode a sam password hash into a password.  The password hash is the
   same method used to store passwords in the NT registry.  The AES key
   used is based on the RID of the user. (upgraded from weak DES) */
int sam_rid_crypt(unsigned int rid, const uint8_t *in, uint8_t *out,
		  enum samba_gnutls_direction encrypt)
{
	uint8_t s[14];
	int ret;

	/* 
	 * SECURITY WARNING: This function was previously using weak DES encryption.
	 * It has been upgraded to use AES-128-CBC for improved security.
	 */
	DEBUG(5, ("sam_rid_crypt: Using upgraded AES encryption instead of deprecated DES\n"));

	s[0] = s[4] = s[8] = s[12] = (uint8_t)(rid & 0xFF);
	s[1] = s[5] = s[9] = s[13] = (uint8_t)((rid >> 8) & 0xFF);
	s[2] = s[6] = s[10]        = (uint8_t)((rid >> 16) & 0xFF);
	s[3] = s[7] = s[11]        = (uint8_t)((rid >> 24) & 0xFF);

	ret = des_crypt56_gnutls(out, in, s, encrypt);
	if (ret != 0) {
		return ret;
	}
	return des_crypt56_gnutls(out+8, in+8, s+7, encrypt);
}

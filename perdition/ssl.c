/**********************************************************************
 * ssl.c                                                  November 2001
 * Horms                                             horms@verge.net.au
 *
 * SSL routines
 *
 * perdition
 * Mail retrieval proxy server
 * Copyright (C) 1999-2005  Horms
 *
 * With assistance from:
 * Eric Rescorla, SSL and TLS - Designing and Building Secure Systems,
 * Addison-Wesley, Reading, MA, USA (2001)
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License as
 * published by the Free Software Foundation; either version 2 of the
 * License, or (at your option) any later version.
 * 
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software Foundation,
 * Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301, USA.
 *
 **********************************************************************/


#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#ifdef WITH_SSL_SUPPORT

#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <termios.h>
#include <string.h>
#include <openssl/bio.h>
#include <openssl/x509v3.h>

#include "ssl.h"
#include "log.h"
#include "io.h"
#include "options.h"
#include "unused.h"

#ifdef DMALLOC
#include <dmalloc.h>
#endif

#include "perdition_globals.h"

#define PERDITION_SSL_CLIENT (flag_t) 0x1
#define PERDITION_SSL_SERVER (flag_t) 0x2

static int __perdition_ssl_passwd_cb(char *buf, int size, int rwflag, 
		void *data);
static int __perdition_verify_callback(int ok, X509_STORE_CTX *ctx);
static long __perdition_verify_result(long verify, X509 *cert);
static int __perdition_ssl_check_common_name(X509 *cert, const char *server);
static int __perdition_ssl_log_certificate(SSL *ssl, X509 *cert);
static int __perdition_ssl_check_certificate(io_t * io, const char *ca_file,
		const char *ca_path, const char *server);
static io_t *__perdition_ssl_connection(io_t *io, SSL_CTX *ssl_ctx, 
		flag_t flag);


struct passwd_cb_data {
	const char *privkey;
};

static int 
__perdition_ssl_passwd_cb(char *buf, int size,
			  int UNUSED(rwflag), void *(data))
{
	ssize_t nbytes;
	struct termios new;
	struct termios old;
	int istty;
	const struct passwd_cb_data *pw_data = (struct passwd_cb_data *)data;

	istty = isatty(0);
	if (!istty && errno == EBADF) {
		VANESSA_LOGGER_DEBUG_ERRNO("isatty");
		return -1;
	}

	if (istty) {
		/* Turn echoing off */
		if (tcgetattr(0, &old) < 0) {
			VANESSA_LOGGER_DEBUG_ERRNO("tcgetattr");
			return -1;
		}
		new = old;
		new.c_lflag &= (~ECHO);
		if(tcsetattr(0, TCSANOW, &new) < 0) {
			VANESSA_LOGGER_DEBUG_ERRNO("tcsetattr");
			return -1;
		}

		/* Prompt user for password */
		fprintf(stderr, "Passphrase for %s: ", pw_data->privkey);
	}

	/* Read Bytes */
	nbytes = read(0, buf, size-1);

	if (istty) {
		/* End prompt */
		fputc('\n', stderr);

		/* Turn echoing on */
		if(tcsetattr(0, TCSANOW, &old) < 0) {
			VANESSA_LOGGER_DEBUG_ERRNO("tcgetattr");
			return -1;
		}
	}

	if(nbytes < 0) {
		VANESSA_LOGGER_DEBUG_ERRNO("read");
		return -1;
	}

	/* Make sure the result is null terminated */
	*(buf + nbytes) = '\0';

	/* Cut of trailing "\n" or trailing "\r\n" */
	if(nbytes > 1 && *(buf + nbytes - 1) == '\n') {
		nbytes--;
		 *(buf + nbytes) = '\0';
		if(nbytes > 1 && *(buf + nbytes - 1) == '\r') {
			nbytes--;
		 	*(buf + nbytes) = '\0';
		}
	}

	return nbytes;
}


/**********************************************************************
 * perdition_ssl_ctx
 * Create an SSL context
 * pre: ca_file: certificate authorities to use. May be NULL
 *               See SSL_CTX_load_verify_locations(3)
 *               Used before ca_path.
 *      ca_path: certificate authorities to use. May be NULL
 *               See SSL_CTX_load_verify_locations(3)
 *               Used after ca_path.
 *      cert: certificate to use. May be NULL if privkey is NULL. 
 *            Should the path to a PEM file if non-NULL and the
 *            first item in the PEM file will be used as the 
 *            certificate.
 *      privkey: private key to use May be NULL if cert is NULL. 
 *               Should the path to a PEM file if non-NULL and the
 *               first item in the PEM file will be used as the 
 *               private key.
 *      ca_chain_file: Sets the optional all-in-one file where you 
 *               can assemble the certificates of Certification Authorities 
 *               (CA) which form the certificate chain of the server 
 *               certificate. This starts with the issuing CA certificate 
 *               of the "ssl_cert_file" certificate and can range up to 
 *               the root CA certificate. Such a file is simply the
 *               concatenation of the various PEM-encoded CA Certificate 
 *               files, usually in certificate chain order.  
 *               Overrides ca_pat and ca_file
 *      ciphers: cipher list to use as per ciphers(1). 
 *               May be NULL in which case openssl's default is used.
 * post: If SSL is initiated and a context is created
 *       If cert is non-NULL then this certificate file is loaded
 *       If privkey is non-NULL then this private key file is loaded
 *       If cert and privkey are non-NULL then check private key
 *       against certificate.
 *       Note: If either cert of privkey are non-NULL then both must
 *       be non-NULL.
 *       If chain_file is not null, it must contain alist of (syntactically)
 *       valid pem-encoded certificates 
 *
 **********************************************************************/

static int
__perdition_verify_callback_debug(X509 *cert, int depth)
{
	char *tmp_str;
	BIO *tmp_bio;
	long len;
	int status = 0;

	if (!opt.debug)
		return 1;

	tmp_bio = BIO_new(BIO_s_mem());
	if (!tmp_bio) {
		VANESSA_LOGGER_DEBUG("BIO_new");
		return 0;
	}

	X509_NAME_print_ex(tmp_bio, X509_get_subject_name(cert),
			   3, XN_FLAG_ONELINE);
	len = BIO_get_mem_data(tmp_bio, &tmp_str);

	tmp_str = strn_to_str(tmp_str, len);
	if (!tmp_str) {
		VANESSA_LOGGER_DEBUG("BIO_new");
		goto err;
	}

	VANESSA_LOGGER_DEBUG_RAW_UNSAFE("depth:%d cert:\"%s\"", depth, tmp_str);

	str_free(tmp_str);
	status = 1;
err:
	if (!BIO_free(tmp_bio)) {
		VANESSA_LOGGER_DEBUG("BIO_free");
		return 0;
	}
	return status;
}

static int 
__perdition_verify_callback(int ok, X509_STORE_CTX *ctx)
{
	X509 *cert = X509_STORE_CTX_get_current_cert(ctx);
	int depth = X509_STORE_CTX_get_error_depth(ctx);

	if (!__perdition_verify_callback_debug(cert, depth)) {
		VANESSA_LOGGER_DEBUG("__perdition_verify_callback_debug");
		return 0;
	}

	if (opt.ssl_cert_verify_depth < depth) {
		VANESSA_LOGGER_DEBUG_UNSAFE("Chain too long, try adjusting "
				"ssl_cert_verify_depth: %d > %d",
				X509_STORE_CTX_get_error_depth(ctx), 
				opt.ssl_cert_verify_depth);
		X509_STORE_CTX_set_error(ctx, X509_V_ERR_CERT_CHAIN_TOO_LONG);
		return 0;
	}

	if (__perdition_verify_result(ctx->error, cert) 
			== X509_V_OK) {
		return 1;
	}

	return ok;
}


#define __PERDITION_VERIFY_RESULT_ELEMENT(_key, _value)                     \
	X509_NAME_oneline((_value), buf, MAX_LINE_LENGTH);                  \
	VANESSA_LOGGER_DEBUG_RAW_UNSAFE("%s:\"%s\"", (_key), buf);

static char *
__perdition_verify_result_time(const char *key, ASN1_TIME *time)
{
	BIO *tmp_bio;
	char *tmp_str;
	long len;
	int status = 0;

	tmp_bio = BIO_new(BIO_s_mem());
	if (!tmp_bio) {
		VANESSA_LOGGER_DEBUG("BIO_new");
		return NULL;
	}

	ASN1_TIME_print(tmp_bio, time);
	len = BIO_get_mem_data(tmp_bio, &tmp_str);

	tmp_str = strn_to_str(tmp_str, len);
	if (!tmp_str) {
		VANESSA_LOGGER_DEBUG("BIO_free");
		goto err;
	}


	VANESSA_LOGGER_DEBUG_RAW_UNSAFE("%s:\"%s\"", key, tmp_str);

	status = 1;
err:
	if (!BIO_free(tmp_bio)) {
		VANESSA_LOGGER_DEBUG("BIO_free");
		str_free(tmp_str);
		return NULL;
	}
	return tmp_str;
}

#define __PERDITION_VERIFY_RESULT_TIME(_key, _time, _err)		    \
do {									    \
	char *tmp_str = __perdition_verify_result_time(_key, _time);	    \
	if (!tmp_str)							    \
		verify = _err;						    \
	else {								    \
		VANESSA_LOGGER_DEBUG_RAW_UNSAFE("%s:\"%s\"", _key, tmp_str);\
		str_free(tmp_str);					    \
	}								    \
} while (0)

#define __PERDITION_VERIFY_RESULT_WARN(_msg)                                \
	 VANESSA_LOGGER_DEBUG_RAW("warning: " _msg)
	
#define __PERDITION_VERIFY_RESULT_ERROR(_msg)                               \
	 VANESSA_LOGGER_DEBUG_RAW("error: " _msg)

static long __perdition_verify_result(long verify, X509 *cert) 
{
	char buf[MAX_LINE_LENGTH];

	/*
	 * Handle all error codes. See verify(1) 
	 */
	switch (verify) {
		case X509_V_OK:
			break;
		case X509_V_ERR_UNABLE_TO_GET_ISSUER_CERT:
			__PERDITION_VERIFY_RESULT_ERROR(
					"unable to get issuer certificate");
			__PERDITION_VERIFY_RESULT_ELEMENT("issuer",
				X509_get_issuer_name(cert));
			break;
		case X509_V_ERR_UNABLE_TO_GET_CRL: /* Unused */
			__PERDITION_VERIFY_RESULT_ERROR(
					"unable to get certificate CRL");
			break;
		case X509_V_ERR_UNABLE_TO_DECRYPT_CERT_SIGNATURE:
			__PERDITION_VERIFY_RESULT_ERROR("unable to decrypt "
					"certificate's signature");
			break;
		case X509_V_ERR_UNABLE_TO_DECRYPT_CRL_SIGNATURE: /* Unused */
			__PERDITION_VERIFY_RESULT_ERROR("unable to decrypt "
					"CLR's signature");
			break;
		case X509_V_ERR_UNABLE_TO_DECODE_ISSUER_PUBLIC_KEY:
			__PERDITION_VERIFY_RESULT_ERROR("unable to decode "
					"issuer public key");
			__PERDITION_VERIFY_RESULT_ELEMENT("issuer",
				X509_get_issuer_name(cert));
			break;
		case X509_V_ERR_CERT_SIGNATURE_FAILURE:
			__PERDITION_VERIFY_RESULT_ERROR(
					"certificate signature failure");
			break;
		case X509_V_ERR_CRL_SIGNATURE_FAILURE: /* Unused */
			__PERDITION_VERIFY_RESULT_ERROR(
					"CRL signature failure");
			break;
		case X509_V_ERR_CERT_NOT_YET_VALID:
			if (opt.ssl_cert_accept_not_yet_valid) {
				__PERDITION_VERIFY_RESULT_WARN(
						"signature not yet valid");
				verify = X509_V_OK;
			}
			else {
				__PERDITION_VERIFY_RESULT_ERROR(
						"signature not yet valid");
			}
			break;
		case X509_V_ERR_CRL_NOT_YET_VALID: /* Unused */
			__PERDITION_VERIFY_RESULT_ERROR(
					"CRL not yet valid");
			__PERDITION_VERIFY_RESULT_TIME("notBefore",
				X509_get_notBefore(cert),
				X509_V_ERR_CRL_NOT_YET_VALID);
			break;
		case X509_V_ERR_CERT_HAS_EXPIRED:
			if (opt.ssl_cert_accept_expired) {
				__PERDITION_VERIFY_RESULT_WARN(
						"certificate has expired");
				verify = X509_V_OK;
			}
			else {
				__PERDITION_VERIFY_RESULT_ERROR(
						"certificate has expired");
			}
			__PERDITION_VERIFY_RESULT_TIME("notAfter",
				X509_get_notAfter(cert),
				X509_V_ERR_CERT_HAS_EXPIRED);
			break;
		case X509_V_ERR_CRL_HAS_EXPIRED: /* Unused */
			__PERDITION_VERIFY_RESULT_ERROR(
					"CLR has expired");
			break;
		case X509_V_ERR_ERROR_IN_CERT_NOT_BEFORE_FIELD:
			__PERDITION_VERIFY_RESULT_ERROR("format error in "
					"certificate's notBefore field");
			__PERDITION_VERIFY_RESULT_TIME("notBefore",
				X509_get_notBefore(cert),
				X509_V_ERR_ERROR_IN_CERT_NOT_BEFORE_FIELD);
			break;
		case X509_V_ERR_ERROR_IN_CERT_NOT_AFTER_FIELD:
			__PERDITION_VERIFY_RESULT_ERROR( "format error in "
					"certificate's notAfter field");
			__PERDITION_VERIFY_RESULT_TIME("notAfter",
				X509_get_notAfter(cert),
				X509_V_ERR_ERROR_IN_CERT_NOT_AFTER_FIELD);
			break;
		case X509_V_ERR_ERROR_IN_CRL_LAST_UPDATE_FIELD: /* Unused */
			__PERDITION_VERIFY_RESULT_ERROR("format error in "
					"CRL's lastUpdate field");
			break;
		case X509_V_ERR_ERROR_IN_CRL_NEXT_UPDATE_FIELD: /* Unused */
			__PERDITION_VERIFY_RESULT_ERROR( "format error in "
					"CRL's nextUpdate field");
			break;
		case X509_V_ERR_OUT_OF_MEM:
			__PERDITION_VERIFY_RESULT_ERROR("out of memory");
			break;
		case X509_V_ERR_DEPTH_ZERO_SELF_SIGNED_CERT:
			if (opt.ssl_cert_accept_self_signed) {
				__PERDITION_VERIFY_RESULT_WARN(
						"self signed certificate");
				verify = X509_V_OK;
			}
			else {
				__PERDITION_VERIFY_RESULT_ERROR(
						"self signed certificate");
			}
			break;
		case X509_V_ERR_SELF_SIGNED_CERT_IN_CHAIN:
			if (opt.ssl_ca_accept_self_signed) {
				__PERDITION_VERIFY_RESULT_WARN("self signed "
						"certificate in chain");
				verify = X509_V_OK;
			}
			else {
				__PERDITION_VERIFY_RESULT_ERROR("self signed "
						"certificate in chain");
			}
			break;
		case X509_V_ERR_UNABLE_TO_GET_ISSUER_CERT_LOCALLY:
			__PERDITION_VERIFY_RESULT_ERROR("unable to get "
					"local issuer certificate");
			break;
		case X509_V_ERR_UNABLE_TO_VERIFY_LEAF_SIGNATURE:
			__PERDITION_VERIFY_RESULT_ERROR("unable to verify "
					"the first certificate");
			break;
		case X509_V_ERR_CERT_CHAIN_TOO_LONG: /* Unused */
			__PERDITION_VERIFY_RESULT_ERROR(
					"certificate chain too long");
			break;
		case X509_V_ERR_CERT_REVOKED: /* Unused */
			__PERDITION_VERIFY_RESULT_ERROR(
					"certificate revoked");
			break;
		case X509_V_ERR_INVALID_CA:
			__PERDITION_VERIFY_RESULT_ERROR(
					"invalid CA certificate");
			break;
		case X509_V_ERR_PATH_LENGTH_EXCEEDED:
			__PERDITION_VERIFY_RESULT_ERROR(
					"path length constraint exceeded");
			break;
		case X509_V_ERR_INVALID_PURPOSE:
			__PERDITION_VERIFY_RESULT_ERROR(
					"unsupported certificate purpose");
			break;
		case X509_V_ERR_CERT_UNTRUSTED:
			__PERDITION_VERIFY_RESULT_ERROR(
					"certificate not trusted");
			break;
		case X509_V_ERR_SUBJECT_ISSUER_MISMATCH:
			__PERDITION_VERIFY_RESULT_ERROR(
					"subject issuer mismatch");
			__PERDITION_VERIFY_RESULT_ELEMENT("subject",
				X509_get_subject_name(cert));
			__PERDITION_VERIFY_RESULT_ELEMENT("issuer",
				X509_get_issuer_name(cert));
			break;
		case X509_V_ERR_AKID_SKID_MISMATCH:
			__PERDITION_VERIFY_RESULT_ERROR("authority and "
					"subject key identifier mismatch");
			break;
		case X509_V_ERR_KEYUSAGE_NO_CERTSIGN:
			__PERDITION_VERIFY_RESULT_ERROR("key usage does "
					"not include certificate signing");
			break;
		case X509_V_ERR_APPLICATION_VERIFICATION: /* Unused */
			__PERDITION_VERIFY_RESULT_ERROR(
					"application verification failure");
			break;
	}

	return(verify);
}

SSL_CTX *perdition_ssl_ctx(const char *ca_file, const char *ca_path, 
		const char *cert, const char *privkey, 
		const char *ca_chain_file, const char *ciphers)
{
	SSL_METHOD *ssl_method;
	SSL_CTX *ssl_ctx;
	const char *use_ca_file = NULL;
	const char *use_ca_path = NULL;
	struct passwd_cb_data pw_data;

	/* 
	 * If either the certificate or private key is non-NULL the
	 * other should be too
	 */
	if (!cert && privkey) {
		VANESSA_LOGGER_DEBUG("Certificate is NULL but "
				"private key is non-NULL");
		return NULL;
	}

	if (!privkey && cert) {
		VANESSA_LOGGER_DEBUG ("Private key is NULL but "
				"certificate is non-NULL");
		return NULL;
	}

	/*
	 * Initialise an SSL context
	 */
	SSLeay_add_ssl_algorithms();
	ssl_method = SSLv23_method();
	SSL_load_error_strings();

	ssl_ctx = SSL_CTX_new(ssl_method);
	if (!ssl_ctx) {
		PERDITION_DEBUG_SSL_ERR("SSL_CTX_new");
		return NULL;
	}

	/*
	 * Set the available ciphers
	 */
	if(ciphers && SSL_CTX_set_cipher_list(ssl_ctx, ciphers) < 0) {
		VANESSA_LOGGER_DEBUG_UNSAFE(
				"Cipher string supplied (%s) "
				"results in no available ciphers",
				ciphers);
	}

	/*
	 * Load and check the certificate and private key
	 */
	if (cert && SSL_CTX_use_certificate_chain_file(ssl_ctx, cert) <= 0) {
		PERDITION_DEBUG_SSL_ERR_UNSAFE
		    ("SSL_CTX_use_certificate_chain_file: \"%s\"", cert);
		VANESSA_LOGGER_ERR_UNSAFE
		    ("Error loading certificate chain file \"%s\"", cert);
		SSL_CTX_free(ssl_ctx);
		return NULL;
	}

	SSL_CTX_set_default_passwd_cb(ssl_ctx, __perdition_ssl_passwd_cb);
	pw_data.privkey = privkey;
	SSL_CTX_set_default_passwd_cb_userdata(ssl_ctx, &pw_data);
	if (cert && SSL_CTX_use_PrivateKey_file(ssl_ctx, privkey, 
			SSL_FILETYPE_PEM) <= 0) {
		PERDITION_DEBUG_SSL_ERR_UNSAFE
		    ("SSL_CTX_use_PrivateKey_file: \"%s\"", privkey);
		VANESSA_LOGGER_ERR_UNSAFE
		    ("Error loading private key file \"%s\"", privkey);
		SSL_CTX_free(ssl_ctx);
		return NULL;
	}

	if (opt.ssl_no_cert_verify)
		return ssl_ctx;

	/* 
	 * Load the Certificate Authorities 
	 */
	use_ca_file = (ca_file && *ca_file) ? ca_file : NULL;
	use_ca_path = (ca_path && *ca_path) ? ca_path : NULL;
	if ((use_ca_file || use_ca_path) &&
			!SSL_CTX_load_verify_locations(ssl_ctx, use_ca_file, 
				use_ca_path)) {
		PERDITION_DEBUG_SSL_ERR_UNSAFE(
				"SSL_CTX_load_verify_locations: "
		     		"file=\"%s\" path=\"%s\"", 
				str_null_safe(use_ca_file), 
				str_null_safe(use_ca_path));
		VANESSA_LOGGER_ERR_UNSAFE
		    ("Error loading certificate authority: " 
		     "file=\"%s\" path=\"%s\"", str_null_safe(use_ca_file),
		     str_null_safe(use_ca_path)); 
		SSL_CTX_free(ssl_ctx);
		return NULL;
	}
	SSL_CTX_set_verify_depth(ssl_ctx, opt.ssl_cert_verify_depth + 1);

	SSL_CTX_set_verify(ssl_ctx, SSL_VERIFY_PEER|SSL_VERIFY_CLIENT_ONCE, 
			__perdition_verify_callback);

	/* NB: We do not need to call SSL_CTX_check_private_key()
	 * because SSL_CTX_set_verify_depth has been called */

	/* try to load the certificate chain file if it is not null*/
	if (ca_chain_file) {
		if (!SSL_CTX_load_verify_locations(ssl_ctx, ca_chain_file, 
					NULL)) {
			PERDITION_DEBUG_SSL_ERR_UNSAFE(
					"SSL_CTX_load_verify_locations: "
					"could not load CA file %s", 
					ca_chain_file);
			SSL_CTX_free(ssl_ctx);
			return NULL;
		}
	}

	return ssl_ctx;
}


/**********************************************************************
 * __perdition_ssl_compare
 * pre: key:  name to match, null terminated
 *      val: value to match against
 *      val_len: length of value in bytes
 * post: none
 * return: 0 on success
 *         -2 if the common key does not match
 **********************************************************************/

static int
__perdition_ssl_compare_key(const char *key, const void *val, size_t val_len)
{
	const char *domain;

	if(strlen(key) == val_len && !memcmp(key, val, val_len))
		return 0;

	/* A wild card common name is allowed
	 * It should be of the form *.domain */
	if (!memcmp(val, "*.", 2)) {
	        domain = strchr(key, '.');
		if (domain && strlen(domain) == val_len - 1 &&
		    !memcmp(domain, val + 1, val_len - 1))
			return 0;
	}

	return -2;
}


/**********************************************************************
 * __perdition_ssl_check_common_name
 * pre: cert: certificate to check the common names of
 *      key:  name to match
 * post: none
 * return: 0 on success
 *         -1 on error
 *         -2 if the common name does not match
 **********************************************************************/

static int 
__perdition_ssl_check_common_name(X509 *cert, const char *key)
{
	int i;
	size_t key_len;
	X509_NAME_ENTRY *e;
	X509_NAME *name;

	name = X509_get_subject_name(cert);
	if (!name) {
		VANESSA_LOGGER_DEBUG_RAW("warning: could not extract "
					 "name from certificate");
		return -1;
	}

	key_len = strlen(key);

	i = -1;
	while (1) {
		i = X509_NAME_get_index_by_NID(name, NID_commonName, i);
		if (i == -1)
			break;

		e = X509_NAME_get_entry(name, i);
		if (!e) {
			VANESSA_LOGGER_DEBUG_RAW_UNSAFE("warning: could not "
				"extract name entry %d from certificate", i);
			return -1;
		}

		if (!__perdition_ssl_compare_key(key, e->value->data,
						 e->value->length))
			return 0;
	}

	return -2;
}


/**********************************************************************
 * __perdition_ssl_check_alt_subject
 * pre: cert: certificate to check the names of
 *      key:  name to match
 * post: none
 * return: 0 on success
 *         -1 on error
 *         -2 if the common name does not match
 **********************************************************************/

static int
__perdition_ssl_check_alt_subject(X509 *cert, const char *key)
{
	int i, count, len, status = 0;
	char *str;
	BIO *bio;
	GENERAL_NAME *gn;
	STACK_OF(GENERAL_NAME) *gns;

	gns = (GENERAL_NAMES*)X509_get_ext_d2i(cert,
			NID_subject_alt_name, NULL, NULL);
	if (!gns) {
		VANESSA_LOGGER_DEBUG_RAW("warning: could not "
			"extract extensions from certificate");
		return -1;
	}

	bio = BIO_new(BIO_s_mem());
	if (!bio) {
		VANESSA_LOGGER_DEBUG("BIO_new");
		return -1;
	}

	count = sk_GENERAL_NAME_num(gns);
	for (i = 0; i < count; i++) {
		gn = sk_GENERAL_NAME_value(gns, i);
		if (!gn) {
			VANESSA_LOGGER_DEBUG_RAW_UNSAFE("warning: "
				"could not extract alt subject %d "
				"from certificate", i);
			status = -1;
			goto out;
		}

		if (gn->type != GEN_DNS)
			continue;

		ASN1_STRING_print_ex(bio, gn->d.dNSName, ASN1_STRFLGS_RFC2253);
		len = BIO_get_mem_data(bio, &str);

		if (!__perdition_ssl_compare_key(key, str, len))
			goto out;

		if (BIO_reset(bio) != 1) {
			VANESSA_LOGGER_DEBUG("BIO_reset");
			status = -1;
			goto out;
		}
	}

	status = -2;
out:
	if (!BIO_free(bio)) {
		VANESSA_LOGGER_DEBUG("BIO_free");
		return -1;
	}
	return status;
}


/**********************************************************************
 * __perdition_ssl_check_name
 * pre: cert: certificate to check the common names and alt subjects of
 *      key:  name to match
 * post: none
 * return: 0 on success
 *         -1 on error
 *         -2 if the common name did not match, or the cert did
 *            not exist
 **********************************************************************/

static int
__perdition_ssl_check_name(X509 *cert, const char *key)
{
	int rc;

	if (opt.ssl_no_cn_verify || !key)
		return 0;

	if (!cert) {
		VANESSA_LOGGER_DEBUG_RAW("warning: no server certificate");
		return -2;
	}

	rc = __perdition_ssl_check_common_name(cert, key);
	if (rc == 0)
	    return 0;
	else if (rc == -1) {
		VANESSA_LOGGER_DEBUG("__perdition_ssl_check_common_name");
		return -1;
	}

	rc = __perdition_ssl_check_alt_subject(cert, key);
	if (rc == 0)
	    return 0;
	else if (rc == -1) {
		VANESSA_LOGGER_DEBUG("__perdition_ssl_check_alt_subject");
		return -1;
	}

	VANESSA_LOGGER_DEBUG_RAW("error: common name mismatch");
	return -2;
}


/**********************************************************************
 * __perdition_ssl_check_certificate
 * Log the details of a certificate
 * pre: ssl: SSL object to log
 *      cert: certificate to log
 * post: details of certificate are logged, if there is one
 * return: 0 on success, including if there was nothing to do
 *         -1 on error
 **********************************************************************/


static int 
__perdition_ssl_log_certificate(SSL *ssl, X509 *cert)
{
	char *str = NULL;

	if (!opt.debug)
		return 0;

	VANESSA_LOGGER_DEBUG_RAW_UNSAFE("SSL connection using %s",
				    SSL_get_cipher(ssl));

	if (!cert)
		return 0;
	
	str = X509_NAME_oneline(X509_get_subject_name(cert), 0, 0);
	if (!str) {
		PERDITION_DEBUG_SSL_ERR("X509_NAME_oneline");
		return 1;
	}
	VANESSA_LOGGER_DEBUG_RAW_UNSAFE("subject: %s", str);
	free(str);

	str = X509_NAME_oneline(X509_get_issuer_name(cert), 0, 0);
	if (!str) {
		PERDITION_DEBUG_SSL_ERR("X509_NAME_oneline");
		return -1;
	}
	VANESSA_LOGGER_DEBUG_RAW_UNSAFE("issuer: %s", str);

	free(str);
	return 0;
}


/**********************************************************************
 * __perdition_ssl_check_certificate
 * Check the details of a certificate
 * pre: io: connection to check certificate of
 *      ca_file: certificate authorities to use. May be NULL
 *               See SSL_CTX_load_verify_locations(3)
 *      ca_path: certificate authorities to use. May be NULL
 *               See SSL_CTX_load_verify_locations(3)
 *      server: server to match the common name of
 * post: details of certificate are logged, if there is one
 *       common name of the certificate is verified
 * return: 0 on success, including if there was nothing to do
 *         -1 on error
 *         -2 if common name mismatched server
 *         -3 if certificate was not verified
 **********************************************************************/


static int 
__perdition_ssl_check_certificate(io_t * io, const char *ca_file,
		const char *ca_path, const char *server)
{
	X509 *cert = NULL;
	SSL *ssl;
	int status = 0;

	ssl = io_get_ssl(io);
	if (!ssl) {
		VANESSA_LOGGER_DEBUG("vanessa_socket_get_ssl");
		status = -1;
		goto leave;
	}
	cert = SSL_get_peer_certificate(ssl);

	status = __perdition_ssl_log_certificate(ssl, cert);
	if (status < 0) {
		VANESSA_LOGGER_DEBUG("__perdition_ssl_log_certificate");
		goto leave;
	}

	if (!opt.ssl_no_cert_verify &&
			((ca_file && *ca_file) || (ca_path && *ca_path)) &&
			__perdition_verify_result(SSL_get_verify_result(ssl),
				cert) != X509_V_OK) {
		VANESSA_LOGGER_ERR("Certificate was not verified");
		PERDITION_DEBUG_SSL_ERR("SSL_get_verify_result");
		status = -3;
		goto leave;
	}

	status = __perdition_ssl_check_name(cert, server);
	if (status < 0) {
		VANESSA_LOGGER_DEBUG("__perdition_ssl_check_name");
		goto leave;
	}

leave:
	if(cert)
		X509_free(cert);

	return status;
}


/**********************************************************************
 * __perdition_ssl_connection
 * Change a stdio based connection into an SSL connection
 * pre: io: io_t to change
 *      ssl_ctx: SSL Context to use
 *      flag: If PERDITION_SSL_CLIENT the io is a client that has 
 *            connected to a server and SSL_connect() will be called. 
 *            If PERDITION_SSL_SERVER then the io is a server that 
 *            has accepted a connection and SSL_accept will be called.
 *            There are no other valid values for flag.
 * post: io_t has an ssl object associated with it and SSL is initiated
 *       for the connection.
 * return: io_t with ssl object associated with it
 *         NULL on error
 **********************************************************************/

static io_t *__perdition_ssl_connection(io_t *io, SSL_CTX *ssl_ctx, 
		flag_t flag)
{
	io_t *new_io = NULL;
	SSL *ssl = NULL;
	int ret;

	ssl = SSL_new(ssl_ctx);
	if (!ssl) {
		PERDITION_DEBUG_SSL_ERR("SSL_new");
		goto bail;
	}

	/* Set up io object that will use SSL */
	new_io = io_create_ssl(ssl, io_get_rfd(io), io_get_wfd(io),
			  io_get_name(io));
	if (!new_io) {
		VANESSA_LOGGER_DEBUG("io_create_ssl");
		goto bail;
	}

	io_set_timeout(new_io, io_get_timeout(io));
	io_destroy(io);
	io = NULL;

	/* Get for TLS/SSL handshake */
	if (flag & PERDITION_SSL_CLIENT) {
		SSL_set_connect_state(ssl);
		ret = SSL_connect(ssl);
		if (ret <= 0) {
			PERDITION_DEBUG_SSL_IO_ERR("SSL_connect",
					io_get_ssl(new_io), ret);
			goto bail;
		}
	} 
	else {
		SSL_set_accept_state(ssl);
		ret = SSL_accept(ssl);
		if (ret <= 0) {
			PERDITION_DEBUG_SSL_IO_ERR("SSL_accept",
					io_get_ssl(new_io), ret);
			VANESSA_LOGGER_DEBUG("no shared ciphers?");
			goto bail;
		}
	}

	return (new_io);

bail:
	if (new_io) {
		io_close(new_io);
		io_destroy(new_io);
	} 
	else if (ssl) {
		SSL_free(ssl);
	}
	if (io)
		io_destroy(io);
	return NULL;
}


/**********************************************************************
 * perdition_ssl_client_connection
 * Change a stdio based connection to a remote server, into an SSL 
 * connection.
 * pre: io: io_t to change. A client that has connected to a server, 
 *          SSL_connect() will be called.
 *      ca_file: certificate authorities to use. May be NULL
 *               See SSL_CTX_load_verify_locations(3)
 *      ca_path: certificate authorities to use. May be NULL
 *               See SSL_CTX_load_verify_locations(3)
 *      ciphers: cipher list to use as per ciphers(1). 
 *               May be NULL in which case openssl's default is used.
 *      server: server name to verify with the common name in
 *              the server's certificate
 * post: io_t has an ssl object associated with it and SSL is initiated
 *       for the connection.
 * return: io_t with ssl object associated with it
 *         NULL on error
 **********************************************************************/

io_t *
perdition_ssl_client_connection(io_t * io, const char *ca_file,
		const char *ca_path, const char *ciphers, const char *server)
{
	SSL_CTX *ssl_ctx;
	io_t *new_io;

	ssl_ctx = perdition_ssl_ctx(ca_file, ca_path, NULL, NULL, NULL,
			ciphers);
	if (!ssl_ctx) {
		PERDITION_DEBUG_SSL_ERR("perdition_ssl_ctx");
		io_destroy(io);
		return NULL;
	}

	new_io = __perdition_ssl_connection(io, ssl_ctx, PERDITION_SSL_CLIENT);
	if (!new_io) {
		VANESSA_LOGGER_DEBUG("perdition_ssl_connection");
		return NULL;
	}

	if (__perdition_ssl_check_certificate(new_io, ca_file, ca_path,
				server) < 0) {
		VANESSA_LOGGER_DEBUG("perdition_ssl_check_certificate");
		io_destroy(new_io);
		return NULL;
	}

	return new_io;
}


/**********************************************************************
 * perdition_ssl_server_connection
 * Change a stdio based connection that receives client connections,
 * into an SSL connection
 * pre: io: io_t to change
 *      ssl_ctx: SSL Context to use
 * post: io_t has an ssl object associated with it and SSL is initiated
 *       for the connection.
 * return: io_t with ssl object associated with it
 *         NULL on error
 **********************************************************************/

io_t *
perdition_ssl_server_connection(io_t * io, SSL_CTX * ssl_ctx)
{
	io_t *new_io;

	new_io = __perdition_ssl_connection(io, ssl_ctx, PERDITION_SSL_SERVER);
	if (!new_io) {
		VANESSA_LOGGER_DEBUG("perdition_ssl_connection");
		return NULL;
	}

	if (__perdition_ssl_check_certificate(new_io, NULL, NULL, NULL) < 0) {
		VANESSA_LOGGER_DEBUG("perdition_ssl_check_certificate");
		io_destroy(new_io);
		return NULL;
	}

	return new_io;
}

#endif				/* WITH_SSL_SUPPORT */

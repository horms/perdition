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
	int fd;
};

static int 
__perdition_ssl_passwd_cb(char *buf, int size,
			  int UNUSED(rwflag), void *data)
{
	ssize_t nbytes;
	struct termios new;
	struct termios old;
	int istty;
	const struct passwd_cb_data *pw_data = (struct passwd_cb_data *)data;
	char *p;

	istty = isatty(pw_data->fd);
	if (!istty && errno == EBADF) {
		VANESSA_LOGGER_DEBUG_ERRNO("isatty");
		return -1;
	}

	if (istty) {
		/* Turn echoing off */
		if (tcgetattr(pw_data->fd, &old) < 0) {
			VANESSA_LOGGER_DEBUG_ERRNO("tcgetattr");
			return -1;
		}
		new = old;
		new.c_lflag &= (~ECHO);
		if(tcsetattr(pw_data->fd, TCSANOW, &new) < 0) {
			VANESSA_LOGGER_DEBUG_ERRNO("tcsetattr");
			return -1;
		}

		/* Prompt user for password */
		fprintf(stderr, "Passphrase for %s: ", pw_data->privkey);
	}

	/* Read Bytes */
	nbytes = read(pw_data->fd, buf, size - 1);

	if (istty) {
		/* End prompt */
		fputc('\n', stderr);

		/* Turn echoing on */
		if(tcsetattr(pw_data->fd, TCSANOW, &old) < 0) {
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

	/* Truncate at the first "\n" or "\r" */
	p = strchr(buf, '\n');
	if (p)
		*p = '\0';
	p = strchr(buf, '\r');
	if (p)
		*p = '\0';

	return strlen(buf);
}

int perdition_parse_ssl_proto_version(const char *str)
{
	if (!strcasecmp(str, "sslv3")) {
		return SSL3_VERSION;
	}
	if (!strcasecmp(str, "tlsv1")) {
		return TLS1_VERSION;
	}
	if (!strcasecmp(str, "tlsv1.1")) {
		return TLS1_1_VERSION;
	}
	if (!strcasecmp(str, "tlsv1.2")) {
		return TLS1_2_VERSION;
	}

	return -1;
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
 *      dh_params_file: Diffie-Hellman parameters to use as a server
 *               May be NULL if not a server, if the DH params are
 *               appended to the cert file, or if EDH ciphersuites are
 *               not desired.  Should be the path to a PEM file that
 *               contains DH PARAMETERS
 *      ciphers: cipher list to use as per ciphers(1). 
 *               May be NULL in which case openssl's default is used.
 *      flag: PERDITION_SSL_CLIENT or PERDITION_SSL_SERVER
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

	if (__perdition_verify_result(X509_STORE_CTX_get_error(ctx),
				      cert) == X509_V_OK)
		return 1;

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

#if HAVE_DECL_SSL_CTX_SET_MIN_PROTO_VERSION == 0
static int
perdition_ssl_ctx_set_min_proto_version(SSL_CTX *ssl_ctx, int min_version)
{
	long options = SSL_OP_NO_SSLv2;

	switch (min_version) {
	case TLS1_2_VERSION:
		options |= SSL_OP_NO_TLSv1_1;
		/* fall-through */
	case TLS1_1_VERSION:
		options |= SSL_OP_NO_TLSv1;
		/* fall-through */
	case TLS1_VERSION:
		options |= SSL_OP_NO_SSLv3;
		/* fall-through */
	case SSL3_VERSION:
		/* Nothing more to do */
		break;
	default:
		PERDITION_DEBUG_SSL_ERR("Unknown minumum version");
		return 0;
	}

	SSL_CTX_set_options(ssl_ctx, options);
	return 1;
}

#define SSL_CTX_set_min_proto_version perdition_ssl_ctx_set_min_proto_version
#endif

#if HAVE_DECL_SSL_CTX_SET_MAX_PROTO_VERSION == 0
static int
perdition_ssl_ctx_set_max_proto_version(SSL_CTX *ssl_ctx, int max_version)
{
	long options = 0;

	switch (max_version) {
	case SSL3_VERSION:
		options |= SSL_OP_NO_TLSv1;
		/* fall-through */
	case TLS1_VERSION:
		options |= SSL_OP_NO_TLSv1_1;
		/* fall-through */
	case TLS1_1_VERSION:
		options |= SSL_OP_NO_TLSv1_2;
		/* fall-through */
	case TLS1_2_VERSION:
		/* Nothing more to do */
		break;
	default:
		PERDITION_DEBUG_SSL_ERR("Unknown maximum version");
		return 0;
	}

	SSL_CTX_set_options(ssl_ctx, options);

	VANESSA_LOGGER_ERR("warning: protocol versions greater than tlsv1.2 "
			   "may still be allowed if supported by the SSL/TLS "
			   "implementation");
	return 1;
}

#define SSL_CTX_set_max_proto_version perdition_ssl_ctx_set_max_proto_version
#endif

SSL_CTX *perdition_ssl_ctx(const char *ca_file, const char *ca_path, 
		const char *cert, const char *privkey, 
		const char *ca_chain_file, const char *dh_params_file,
		const char *ciphers, flag_t flag)
{
	SSL_CTX *ssl_ctx, *out = NULL;
	const char *dhfile = NULL;
	FILE* dhfp = NULL;
	DH* dh = NULL;
	EC_KEY* ecdh = NULL;
	const char *use_ca_file = NULL;
	const char *use_ca_path = NULL;
	struct passwd_cb_data pw_data;
	int mode, fd = -1;

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
	SSL_load_error_strings();

	ssl_ctx = SSL_CTX_new(SSLv23_method());
	if (!ssl_ctx) {
		PERDITION_DEBUG_SSL_ERR("SSL_CTX_new");
		return NULL;
	}

	/* Set context for session */
	if (!SSL_CTX_set_session_id_context(ssl_ctx,
					    (unsigned char *)PACKAGE,
					    strlen(PACKAGE))) {
		VANESSA_LOGGER_DEBUG("SSL_CTX_set_session_id_context");
		goto err;
	}

	/*
	 * Set minimum protocol version
	 */
	{
		const char *ver_str;

		if (flag == PERDITION_SSL_CLIENT)
			ver_str = opt.ssl_outgoing_min_proto_version;
		else
			ver_str = opt.ssl_listen_min_proto_version;

		if (ver_str) {
			int ver_no = perdition_parse_ssl_proto_version(ver_str);


			if (ver_no < 0) {
				VANESSA_LOGGER_DEBUG("perdition_parse_ssl_proto_version");
				goto err;
			}

			if (!SSL_CTX_set_min_proto_version(ssl_ctx, ver_no)) {
				VANESSA_LOGGER_DEBUG("SSL_CTX_set_min_proto_version");
				goto err;
			}
		}
	}

	/*
	 * Set maximum protocol version
	 */
	{
		const char *ver_str;

		if (flag == PERDITION_SSL_CLIENT)
			ver_str = opt.ssl_outgoing_max_proto_version;
		else
			ver_str = opt.ssl_listen_max_proto_version;

		if (ver_str) {
			int ver_no = perdition_parse_ssl_proto_version(ver_str);


			if (ver_no < 0) {
				VANESSA_LOGGER_DEBUG("perdition_parse_ssl_proto_version");
				goto err;
			}

			if (!SSL_CTX_set_max_proto_version(ssl_ctx, ver_no)) {
				VANESSA_LOGGER_DEBUG("SSL_CTX_set_max_proto_version");
				goto err;
			}
		}
	}

	/*
	 * Set compression
	 */
	if ((flag == PERDITION_SSL_CLIENT && !opt.ssl_outgoing_compression) &&
	    (flag != PERDITION_SSL_CLIENT && !opt.ssl_listen_compression)) {
		SSL_CTX_set_options(ssl_ctx, SSL_OP_NO_COMPRESSION);
	}

	/*
	 * Set cipher server preference
	 */
	if ((flag == PERDITION_SSL_SERVER &&
	     !opt.ssl_no_cipher_server_preference))
		SSL_CTX_set_options(ssl_ctx, SSL_OP_CIPHER_SERVER_PREFERENCE);

	/*
	 * Load the Diffie-Hellman parameters:
	 */
	if (flag & PERDITION_SSL_SERVER &&
		(dh_params_file || cert)) {
		dhfile = (dh_params_file ? dh_params_file : cert);
		dhfp = fopen(dhfile, "r");
		if (dhfp == NULL) {
			if (dh_params_file) {
				VANESSA_LOGGER_ERR_UNSAFE
					("Error opening Diffie-Hellman parameters file \"%s\"", dhfile);
				SSL_CTX_free(ssl_ctx);
				return NULL;
			} else {
				VANESSA_LOGGER_DEBUG_UNSAFE("could not open cert file for reading DH params \"%s\"", dhfile);
			}
		} else {
			dh = PEM_read_DHparams(dhfp, NULL, NULL, NULL);
			fclose(dhfp);
			if (dh == NULL) {
				if (dh_params_file) {
					PERDITION_DEBUG_SSL_ERR("PEM_read_DHparams");
					VANESSA_LOGGER_ERR_UNSAFE
						("Error reading Diffie-Hellman parameters from file \"%s\"", dhfile);
					SSL_CTX_free(ssl_ctx);
					return NULL;
				} else {
					VANESSA_LOGGER_ERR_UNSAFE("could not read DH params from cert file \"%s\"", dhfile);
				}
			} else {
				if (1 != SSL_CTX_set_tmp_dh(ssl_ctx, dh)) {
					PERDITION_DEBUG_SSL_ERR("SSL_CTX_set_tmp_dh");
					VANESSA_LOGGER_ERR_UNSAFE
					("Error loading Diffie-Hellman parameters: \"%s\"", dhfile);
				} else {
					VANESSA_LOGGER_INFO_UNSAFE
					("Loaded Diffie-Hellman parameters: \"%s\"", dhfile);
				}
				DH_free(dh);
				SSL_CTX_set_options(ssl_ctx, SSL_OP_SINGLE_DH_USE);
			}
		}
	}		  


	/*
	 * Load the EC Diffie-Hellman parameters:
	 */
	if (flag & PERDITION_SSL_SERVER) {
		EC_KEY *ecdh = EC_KEY_new_by_curve_name (NID_X9_62_prime256v1);
		if (!ecdh) {
			VANESSA_LOGGER_ERR("Error generating ECDH parameters");
		} else {
			if (!SSL_CTX_set_tmp_ecdh (ssl_ctx, ecdh)) {
				VANESSA_LOGGER_ERR("Error setting ECDH parameters");
		 	}
			EC_KEY_free (ecdh);
		}
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
	if (opt.ssl_passphrase_file) {
		fd = open(opt.ssl_passphrase_file, O_RDONLY);
		if (fd < 0) {
			VANESSA_LOGGER_DEBUG_UNSAFE("Could not open "
						    "passphrase-file "
						    "[%s]: %s",
						    opt.ssl_passphrase_file,
						    strerror(errno));
			goto err;
		}
		pw_data.fd = fd;
	}
	else
		pw_data.fd = opt.ssl_passphrase_fd;

	SSL_CTX_set_default_passwd_cb_userdata(ssl_ctx, &pw_data);

	if (cert && SSL_CTX_use_PrivateKey_file(ssl_ctx, privkey, 
			SSL_FILETYPE_PEM) <= 0) {
		PERDITION_DEBUG_SSL_ERR_UNSAFE
		    ("SSL_CTX_use_PrivateKey_file: \"%s\"", privkey);
		VANESSA_LOGGER_ERR_UNSAFE
		    ("Error loading private key file \"%s\"", privkey);
		goto err;
	}

	if (flag & PERDITION_SSL_CLIENT && opt.ssl_no_cert_verify)
		goto out;

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
		goto err;
	}
	SSL_CTX_set_verify_depth(ssl_ctx, opt.ssl_cert_verify_depth + 1);

	if (flag & PERDITION_SSL_SERVER &&
	    (opt.ssl_no_cert_verify || opt.ssl_no_client_cert_verify))
		mode = SSL_VERIFY_NONE;
	else
		mode = SSL_VERIFY_PEER|SSL_VERIFY_CLIENT_ONCE;
	SSL_CTX_set_verify(ssl_ctx, mode, __perdition_verify_callback);

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
			goto err;
		}
	}

out:
	out = ssl_ctx;
err:
	if (!out)
		SSL_CTX_free(ssl_ctx);
	if (fd > -1)
		close(fd);
	return out;
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

	/* Need at lest "*." SOMETHING */
	if (val_len < 3)
		return -1;

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
	X509_NAME *name;

	name = X509_get_subject_name(cert);
	if (!name) {
		VANESSA_LOGGER_DEBUG_RAW("warning: could not extract "
					 "name from certificate");
		return -1;
	}

	i = -1;
	while (1) {
		X509_NAME_ENTRY *e;
		ASN1_STRING *data;

		i = X509_NAME_get_index_by_NID(name, NID_commonName, i);
		if (i == -1)
			break;

		e = X509_NAME_get_entry(name, i);
		if (!e) {
			VANESSA_LOGGER_DEBUG_RAW_UNSAFE("warning: could not "
				"extract name entry %d from certificate", i);
			return -1;
		}

		data = X509_NAME_ENTRY_get_data(e);
		if (!data) {
			VANESSA_LOGGER_DEBUG_RAW_UNSAFE("warning: could not "
				"extract data for name entry %d", i);
			return -1;
		}

		if (!__perdition_ssl_compare_key(key, data->data, data->length))
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

#ifdef WITH_LIBIDN
#include <idna.h>

static char *idna_to_ascii(const char *in)
{
	char *out;
	int status;

	status = idna_to_ascii_8z(in, &out, IDNA_USE_STD3_ASCII_RULES);
	if (status) {
		puts(idna_strerror(status));
		return NULL;
	}

	return out;
}

static void idna_str_free(char *out)
{
	free(out);
}

#define IDNA_STR(name) char *(name) = NULL

#else
static const char *idna_to_ascii(const char *in)
{
	return in;
}

static void idna_str_free(const char *UNUSED(out))
{
	;
}

#define IDNA_STR(name) const char *(name) = NULL
#endif

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
	IDNA_STR(idna_key);
	int status = -1;

	if (opt.ssl_no_cn_verify || !key)
		return 0;

	idna_key = idna_to_ascii(key);
	if (!idna_key) {
		VANESSA_LOGGER_DEBUG_RAW("idna_to_ascii");
		goto err;
	}

	if (!cert) {
		VANESSA_LOGGER_DEBUG_RAW("warning: no server certificate");
		goto not_exist;
	}

	rc = __perdition_ssl_check_common_name(cert, idna_key);
	if (rc == 0)
	    return 0;
	else if (rc == -1) {
		VANESSA_LOGGER_DEBUG("__perdition_ssl_check_common_name");
		goto err;
	}

	rc = __perdition_ssl_check_alt_subject(cert, idna_key);
	if (rc == 0)
	    return 0;
	else if (rc == -1) {
		VANESSA_LOGGER_DEBUG("__perdition_ssl_check_alt_subject");
		goto err;
	}

	VANESSA_LOGGER_DEBUG_RAW("error: common name mismatch");
not_exist:
	status = -2;
err:
	idna_str_free(idna_key);
	return status;
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


static int set_socket_timeout(int s, long timeout)
{
	struct timeval tv = { .tv_sec = timeout, .tv_usec = 0 };

	if (setsockopt(s, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv))) {
		VANESSA_LOGGER_DEBUG_ERRNO("setcockopt");
		return -1;
	}

	return 0;
}

static int io_set_socket_timeout(io_t *io, long timeout)
{
        int s;

        s = io_get_rfd(io);
        if (s < 0) {
                VANESSA_LOGGER_DEBUG("io_get_rfd");
                return -1;
        }

        if (set_socket_timeout(s, timeout) < 0) {
                VANESSA_LOGGER_DEBUG("set_socket_timeout(rfd)");
                return -1;
        }

        s = io_get_wfd(io);
        if (s < 0) {
                VANESSA_LOGGER_DEBUG("io_get_wfd");
                return -1;
        }

        if (set_socket_timeout(s, timeout) < 0) {
                VANESSA_LOGGER_DEBUG("set_socket_timeout(wfd)");
                return -1;
        }

        return 0;
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
	long timeout;

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

	timeout = io_get_timeout(io);

	io_set_timeout(new_io, timeout);
	io_destroy(io);
	io = NULL;

	if (io_set_socket_timeout(new_io, timeout) < 0) {
		VANESSA_LOGGER_DEBUG("io_set_socket_timeout(timeout)");
		goto bail;
	}

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
			VANESSA_LOGGER_DEBUG("timeout or no shared ciphers?");
			goto bail;
		}
	}

	if (io_set_socket_timeout(new_io, 0) < 0) {
		VANESSA_LOGGER_DEBUG("io_set_socket_timeout(0)");
		goto bail;
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
			NULL, ciphers, PERDITION_SSL_CLIENT);
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

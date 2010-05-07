#ifndef PERDIION_SASL_PLAIN_H
#define PERDIION_SASL_PLAIN_H

#define SASL_MECHANISM_PLAIN "PLAIN"

/**********************************************************************
 * sasl_plain_challenge_decode
 * Decode a SASL PLAIN challenge
 * pre: challenge: the challenge
 * return: .auth: seeded auth structure
 *         .status: auth_status_ok on success
 *                  auth_status_invalid if the challenge is invalid
 *                  auth_status_error on internal error
 **********************************************************************/

struct auth_status sasl_plain_challenge_decode(const char *challenge);

/**********************************************************************
 * sasl_plain_challenge_encode
 * Encode a SASL PLAIN challenge
 * pre: auth: seeded auth structure
 * return: encoded challenge
 *         NULL on error
 **********************************************************************/

char * sasl_plain_challenge_encode(const struct auth *auth);

#endif /* PERDIION_SASL_PLAIN_H */

/* Define to compile in pam support */
/* #define WITH_PAM_SUPPORT 1 */

/* User to run perdition as */
/* #define WITH_USER "nobody" */

/* Group to run perdition as */
/* #define WITH_GROUP "nobody" */

/* Do we have LDAP LUD extentions */
/* #define WITH_LDAP_LUD_EXTS 1 */

/* Should we use DMALLOC */
/* #define WITH_DMALLOC 1 */

/* Borrowed from Proftpd
 * Proftpd is Licenced under the terms of the GNU General Public Licence
 * and is available from http://www.proftpd.org/
 */

/* Define this if you have the setpassent function */
#undef HAVE_SETPASSENT

/* If you don't have setproctitle, PF_ARGV_TYPE needs to be set to either
 * PF_ARGV_NEW (replace argv[] arguments), PF_ARGV_WRITEABLE (overwrite
 * argv[]), PF_ARGV_PSTAT (use the pstat function), or PF_ARGV_PSSTRINGS
 * (use PS_STRINGS).
 * 
 * configure should, we hope <wink>, detect this for you.
 */
#undef PF_ARGV_TYPE

/* Define if your system has __progname */
#undef HAVE___PROGNAME

/* Define if your system has the setproctitle function */
#undef HAVE_SETPROCTITLE

/* End of code borrowed from proftpd */


AC_INIT(configure.ac)
AC_CONFIG_AUX_DIR([config])
AM_INIT_AUTOMAKE(pam_lxc,0.1)
AC_LANG_C
AC_PROG_CC
AC_DISABLE_STATIC
AC_PROG_LIBTOOL

LT_INIT([shared])

AC_CHECK_LIB(lxc,lxc_attach,[], [
        echo "Missing liblxc.  Could not find lxc_attach.  (you also probably need a modified kernel)."
        exit -1
        ])

dnl
dnl By default, everything under PAM is installed below /usr.
dnl
AC_PREFIX_DEFAULT(/usr)

dnl and some hacks to use /etc and /lib
test "${prefix}" = "NONE" && prefix="/usr"
if test ${prefix} = '/usr'
then
dnl If we use /usr as prefix, use /etc for config files
        if test ${sysconfdir} = '${prefix}/etc'
        then
                sysconfdir="/etc"
        fi
    if test ${libdir} = '${exec_prefix}/lib'
    then
        case "`uname -m`" in
            x86_64|ppc64|s390x|sparc64)
            libdir="/lib64" ;;
            *)
            libdir="/lib" ;;
        esac
    fi
    if test ${sbindir} = '${exec_prefix}/sbin'
        then
                sbindir="/sbin"
        fi
dnl If we use /usr as prefix, use /usr/share/man for manual pages
        if test ${mandir} = '${prefix}/man'
        then
                mandir='${prefix}/share/man'
        fi
dnl Add security to include directory
    if test ${includedir} = '${prefix}/include'
    then
        includedir="${prefix}/include/security"
    fi

dnl Add /var directory
        if test ${localstatedir} = '${prefix}/var'
        then
                localstatedir="/var"
        fi

fi

AC_ARG_ENABLE(securedir,
    AS_HELP_STRING([--enable-securedir=DIR],[path to location of PAMs @<:@default=$libdir/security@:>@]),
    SECUREDIR=$enableval, SECUREDIR=$libdir/security)
AC_SUBST(SECUREDIR)


AC_CHECK_HEADERS(security/pam_appl.h)
if test x$ac_cv_header_security_pam_appl_h != xyes ; then
    AC_MSG_ERROR([you must have PAM development files to build $PACKAGE])
fi
AC_CHECK_HEADERS(security/pam_modules.h)
if test x$ac_cv_header_security_pam_modules_h != xyes ; then
    AC_MSG_ERROR([you must have PAM development files to build $PACKAGE])
fi
AC_CHECK_HEADERS(security/pam_misc.h)

AC_CONFIG_HEADER(config.h)
AC_CONFIG_FILES([
    Makefile
    config/Makefile
    src/Makefile
])

AC_OUTPUT

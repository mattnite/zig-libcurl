const std = @import("std");
const legacy = @import("../../src/main.zig");

fn root() []const u8 {
    return (std.fs.path.dirname(@src().file) orelse ".") ++ "/";
}

fn file() []const u8 {
    return @src().file;
}

pub const paths = legacy.LibraryPaths(BuildConfig){
    .name = "libcurl",
    .zig_bindings = root() ++ "src/main.zig",
    .config_module_path = file(),
    .include_dirs = .{
        .public = &.{root() ++ "curl/include"},
        .private = &.{root() ++ "curl/lib"},
    },
    .source_files = &.{
        root() ++ "curl/lib/hostcheck.c",
        root() ++ "curl/lib/curl_gethostname.c",
        root() ++ "curl/lib/strerror.c",
        root() ++ "curl/lib/strdup.c",
        root() ++ "curl/lib/asyn-ares.c",
        root() ++ "curl/lib/pop3.c",
        root() ++ "curl/lib/bufref.c",
        root() ++ "curl/lib/rename.c",
        root() ++ "curl/lib/nwlib.c",
        root() ++ "curl/lib/file.c",
        root() ++ "curl/lib/curl_gssapi.c",
        root() ++ "curl/lib/ldap.c",
        root() ++ "curl/lib/socketpair.c",
        root() ++ "curl/lib/system_win32.c",
        root() ++ "curl/lib/http_aws_sigv4.c",
        root() ++ "curl/lib/content_encoding.c",
        root() ++ "curl/lib/vquic/ngtcp2.c",
        root() ++ "curl/lib/vquic/quiche.c",
        root() ++ "curl/lib/vquic/vquic.c",
        root() ++ "curl/lib/ftp.c",
        root() ++ "curl/lib/curl_ntlm_wb.c",
        root() ++ "curl/lib/curl_ntlm_core.c",
        root() ++ "curl/lib/hostip.c",
        root() ++ "curl/lib/urlapi.c",
        root() ++ "curl/lib/curl_get_line.c",
        root() ++ "curl/lib/vtls/mesalink.c",
        root() ++ "curl/lib/vtls/mbedtls_threadlock.c",
        root() ++ "curl/lib/vtls/nss.c",
        root() ++ "curl/lib/vtls/gskit.c",
        root() ++ "curl/lib/vtls/wolfssl.c",
        root() ++ "curl/lib/vtls/keylog.c",
        root() ++ "curl/lib/vtls/rustls.c",
        root() ++ "curl/lib/vtls/vtls.c",
        root() ++ "curl/lib/vtls/gtls.c",
        root() ++ "curl/lib/vtls/schannel.c",
        root() ++ "curl/lib/vtls/schannel_verify.c",
        root() ++ "curl/lib/vtls/sectransp.c",
        root() ++ "curl/lib/vtls/openssl.c",
        root() ++ "curl/lib/vtls/mbedtls.c",
        root() ++ "curl/lib/vtls/bearssl.c",
        root() ++ "curl/lib/parsedate.c",
        root() ++ "curl/lib/sendf.c",
        root() ++ "curl/lib/altsvc.c",
        root() ++ "curl/lib/krb5.c",
        root() ++ "curl/lib/curl_rtmp.c",
        root() ++ "curl/lib/curl_ctype.c",
        root() ++ "curl/lib/inet_pton.c",
        root() ++ "curl/lib/pingpong.c",
        root() ++ "curl/lib/mime.c",
        root() ++ "curl/lib/vauth/krb5_gssapi.c",
        root() ++ "curl/lib/vauth/krb5_sspi.c",
        root() ++ "curl/lib/vauth/spnego_sspi.c",
        root() ++ "curl/lib/vauth/digest.c",
        root() ++ "curl/lib/vauth/ntlm_sspi.c",
        root() ++ "curl/lib/vauth/vauth.c",
        root() ++ "curl/lib/vauth/gsasl.c",
        root() ++ "curl/lib/vauth/cram.c",
        root() ++ "curl/lib/vauth/oauth2.c",
        root() ++ "curl/lib/vauth/digest_sspi.c",
        root() ++ "curl/lib/vauth/cleartext.c",
        root() ++ "curl/lib/vauth/spnego_gssapi.c",
        root() ++ "curl/lib/vauth/ntlm.c",
        root() ++ "curl/lib/version_win32.c",
        root() ++ "curl/lib/multi.c",
        root() ++ "curl/lib/http_ntlm.c",
        root() ++ "curl/lib/curl_sspi.c",
        root() ++ "curl/lib/md5.c",
        root() ++ "curl/lib/dict.c",
        root() ++ "curl/lib/http.c",
        root() ++ "curl/lib/curl_des.c",
        root() ++ "curl/lib/memdebug.c",
        root() ++ "curl/lib/non-ascii.c",
        root() ++ "curl/lib/transfer.c",
        root() ++ "curl/lib/inet_ntop.c",
        root() ++ "curl/lib/slist.c",
        root() ++ "curl/lib/http_negotiate.c",
        root() ++ "curl/lib/http_digest.c",
        root() ++ "curl/lib/vssh/wolfssh.c",
        root() ++ "curl/lib/vssh/libssh.c",
        root() ++ "curl/lib/vssh/libssh2.c",
        root() ++ "curl/lib/hsts.c",
        root() ++ "curl/lib/escape.c",
        root() ++ "curl/lib/hostsyn.c",
        root() ++ "curl/lib/speedcheck.c",
        root() ++ "curl/lib/asyn-thread.c",
        root() ++ "curl/lib/curl_addrinfo.c",
        root() ++ "curl/lib/nwos.c",
        root() ++ "curl/lib/tftp.c",
        root() ++ "curl/lib/version.c",
        root() ++ "curl/lib/rand.c",
        root() ++ "curl/lib/psl.c",
        root() ++ "curl/lib/imap.c",
        root() ++ "curl/lib/mqtt.c",
        root() ++ "curl/lib/share.c",
        root() ++ "curl/lib/doh.c",
        root() ++ "curl/lib/curl_range.c",
        root() ++ "curl/lib/openldap.c",
        root() ++ "curl/lib/getinfo.c",
        root() ++ "curl/lib/select.c",
        root() ++ "curl/lib/base64.c",
        root() ++ "curl/lib/curl_sasl.c",
        root() ++ "curl/lib/curl_endian.c",
        root() ++ "curl/lib/connect.c",
        root() ++ "curl/lib/fileinfo.c",
        root() ++ "curl/lib/telnet.c",
        root() ++ "curl/lib/x509asn1.c",
        root() ++ "curl/lib/conncache.c",
        root() ++ "curl/lib/strcase.c",
        root() ++ "curl/lib/if2ip.c",
        root() ++ "curl/lib/gopher.c",
        root() ++ "curl/lib/ftplistparser.c",
        root() ++ "curl/lib/setopt.c",
        root() ++ "curl/lib/idn_win32.c",
        root() ++ "curl/lib/strtoofft.c",
        root() ++ "curl/lib/hmac.c",
        root() ++ "curl/lib/getenv.c",
        root() ++ "curl/lib/smb.c",
        root() ++ "curl/lib/dotdot.c",
        root() ++ "curl/lib/curl_threads.c",
        root() ++ "curl/lib/md4.c",
        root() ++ "curl/lib/easygetopt.c",
        root() ++ "curl/lib/curl_fnmatch.c",
        root() ++ "curl/lib/sha256.c",
        root() ++ "curl/lib/cookie.c",
        root() ++ "curl/lib/amigaos.c",
        root() ++ "curl/lib/progress.c",
        root() ++ "curl/lib/nonblock.c",
        root() ++ "curl/lib/llist.c",
        root() ++ "curl/lib/hostip6.c",
        root() ++ "curl/lib/dynbuf.c",
        root() ++ "curl/lib/warnless.c",
        root() ++ "curl/lib/hostasyn.c",
        root() ++ "curl/lib/http_chunks.c",
        root() ++ "curl/lib/wildcard.c",
        root() ++ "curl/lib/strtok.c",
        root() ++ "curl/lib/curl_memrchr.c",
        root() ++ "curl/lib/rtsp.c",
        root() ++ "curl/lib/http2.c",
        root() ++ "curl/lib/socks.c",
        root() ++ "curl/lib/curl_path.c",
        root() ++ "curl/lib/curl_multibyte.c",
        root() ++ "curl/lib/http_proxy.c",
        root() ++ "curl/lib/formdata.c",
        root() ++ "curl/lib/netrc.c",
        root() ++ "curl/lib/socks_sspi.c",
        root() ++ "curl/lib/mprintf.c",
        root() ++ "curl/lib/easyoptions.c",
        root() ++ "curl/lib/easy.c",
        root() ++ "curl/lib/c-hyper.c",
        root() ++ "curl/lib/hostip4.c",
        root() ++ "curl/lib/timeval.c",
        root() ++ "curl/lib/smtp.c",
        root() ++ "curl/lib/splay.c",
        root() ++ "curl/lib/socks_gssapi.c",
        root() ++ "curl/lib/url.c",
        root() ++ "curl/lib/hash.c",
    },
};

pub const BuildConfig = void;

pub fn configure(
    comptime target: std.zig.CrossTarget,
    comptime mode: std.builtin.Mode,
    comptime linkage: std.build.LibExeObjStep.Linkage,
    comptime config: BuildConfig,
) legacy.ConfigurationResult {
    _ = target;
    _ = mode;
    _ = config;
    const common_defines = &.{
        .{ "CURL_DISABLE_LDAP", "1" },
        .{ "CURL_DISABLE_LDAPS", "1" },
        .{ "USE_MBEDTLS", "1" },
        // disables alt-svc
        // #undef CURL_DISABLE_ALTSVC

        // disables cookies support
        // #undef CURL_DISABLE_COOKIES

        // disables cryptographic authentication
        // #undef CURL_DISABLE_CRYPTO_AUTH

        .{ "CURL_DISABLE_DICT", "1" },
        // disables DNS-over-HTTPS
        // #undef CURL_DISABLE_DOH
        .{ "CURL_DISABLE_FILE", "1" },
        .{ "CURL_DISABLE_FTP", "1" },
        .{ "CURL_DISABLE_GOPHER", "1" },
        // disables HSTS support
        // #undef CURL_DISABLE_HSTS

        // disables HTTP
        // #undef CURL_DISABLE_HTTP

        // disables IMAP
        .{ "CURL_DISABLE_IMAP", "1" },

        // disables --libcurl option from the curl tool
        // #undef CURL_DISABLE_LIBCURL_OPTION

        // #undef CURL_DISABLE_MIME

        .{ "CURL_DISABLE_MQTT", "1" },

        // disables netrc parser
        // #undef CURL_DISABLE_NETRC

        // disables NTLM support
        // #undef CURL_DISABLE_NTLM

        // disables date parsing
        // #undef CURL_DISABLE_PARSEDATE

        .{ "CURL_DISABLE_POP3", "1" },

        // disables built-in progress meter
        // #undef CURL_DISABLE_PROGRESS_METER

        // disables proxies
        // #undef CURL_DISABLE_PROXY

        .{ "CURL_DISABLE_RTSP", "1" },
        .{ "CURL_DISABLE_SMB", "1" },
        .{ "CURL_DISABLE_SMTP", "1" },

        // disables use of socketpair for curl_multi_poll
        // #undef CURL_DISABLE_SOCKETPAIR

        .{ "CURL_DISABLE_TELNET", "1" },
        .{ "CURL_DISABLE_TFTP", "1" },

        // disables verbose strings
        // #undef CURL_DISABLE_VERBOSE_STRINGS

        // Define to 1 if you have the `ssh2' library {-lssh2}.
        .{ "HAVE_LIBSSH2", "1" },

        // Define to 1 if you have the <libssh2.h> header file.
        .{ "HAVE_LIBSSH2_H", "1" },

        // if zlib is available
        .{ "HAVE_LIBZ", "1" },

        // if you have the zlib.h header file
        .{ "HAVE_ZLIB_H", "1" },
    };

    return .{
        .defines = .{
            .public = switch (linkage) {
                .static => &.{.{ "CURL_STATICLIB", "1" }},
                .dynamic => &.{},
            },
            .private = common_defines,
        },
    };
}

//    // disables LDAP
//    ret.defineCMacro("CURL_DISABLE_LDAP", "1");
//
//    // disables LDAPS
//    ret.defineCMacro("CURL_DISABLE_LDAPS", "1");
//
//    // if mbedTLS is enabled
//    ret.defineCMacro("USE_MBEDTLS", "1");
//
//    // disables alt-svc
//    // #undef CURL_DISABLE_ALTSVC
//
//    // disables cookies support
//    // #undef CURL_DISABLE_COOKIES
//
//    // disables cryptographic authentication
//    // #undef CURL_DISABLE_CRYPTO_AUTH
//
//    // disables DICT
//    ret.defineCMacro("CURL_DISABLE_DICT", "1");
//
//    // disables DNS-over-HTTPS
//    // #undef CURL_DISABLE_DOH
//
//    // disables FILE
//    ret.defineCMacro("CURL_DISABLE_FILE", "1");
//
//    // disables FTP
//    ret.defineCMacro("CURL_DISABLE_FTP", "1");
//
//    // disables GOPHER
//    ret.defineCMacro("CURL_DISABLE_GOPHER", "1");
//
//    // disables HSTS support
//    // #undef CURL_DISABLE_HSTS
//
//    // disables HTTP
//    // #undef CURL_DISABLE_HTTP
//
//    // disables IMAP
//    ret.defineCMacro("CURL_DISABLE_IMAP", "1");
//
//    // disables --libcurl option from the curl tool
//    // #undef CURL_DISABLE_LIBCURL_OPTION
//
//    // disables MIME support
//    // #undef CURL_DISABLE_MIME
//
//    // disables MQTT
//    ret.defineCMacro("CURL_DISABLE_MQTT", "1");
//
//    // disables netrc parser
//    // #undef CURL_DISABLE_NETRC
//
//    // disables NTLM support
//    // #undef CURL_DISABLE_NTLM
//
//    // disables date parsing
//    // #undef CURL_DISABLE_PARSEDATE
//
//    // disables POP3
//    ret.defineCMacro("CURL_DISABLE_POP3", "1");
//
//    // disables built-in progress meter
//    // #undef CURL_DISABLE_PROGRESS_METER
//
//    // disables proxies
//    // #undef CURL_DISABLE_PROXY
//
//    // disables RTSP
//    ret.defineCMacro("CURL_DISABLE_RTSP", "1");
//
//    // disables SMB
//    ret.defineCMacro("CURL_DISABLE_SMB", "1");
//
//    // disables SMTP
//    ret.defineCMacro("CURL_DISABLE_SMTP", "1");
//
//    // disables use of socketpair for curl_multi_poll
//    // #undef CURL_DISABLE_SOCKETPAIR
//
//    // disables TELNET
//    ret.defineCMacro("CURL_DISABLE_TELNET", "1");
//
//    // disables TFTP
//    ret.defineCMacro("CURL_DISABLE_TFTP", "1");
//
//    // disables verbose strings
//    // #undef CURL_DISABLE_VERBOSE_STRINGS
//
//    // Define to 1 if you have the `ssh2' library (-lssh2).
//    ret.defineCMacro("HAVE_LIBSSH2", "1");
//
//    // Define to 1 if you have the <libssh2.h> header file.
//    ret.defineCMacro("HAVE_LIBSSH2_H", "1");
//
//    // if zlib is available
//    ret.defineCMacro("HAVE_LIBZ", "1");
//
//    // if you have the zlib.h header file
//    ret.defineCMacro("HAVE_ZLIB_H", "1");
//
//    if (target.isWindows()) {
//        // Define if you want to enable WIN32 threaded DNS lookup
//        //ret.defineCMacro("USE_THREADS_WIN32", "1");
//
//        return Library{ .step = ret, .exported_defines = exported_defines.toOwnedSlice() };
//    }
//
//    //ret.defineCMacro("libcurl_EXPORTS", null);
//
//    //ret.defineCMacro("STDC_HEADERS", null);
//
//    // when building libcurl itself
//    // #undef BUILDING_LIBCURL
//
//    // Location of default ca bundle
//    // ret.defineCMacro("CURL_CA_BUNDLE", "\"/etc/ssl/certs/ca-certificates.crt\"");
//
//    // define "1" to use built-in ca store of TLS backend
//    // #undef CURL_CA_FALLBACK
//
//    // Location of default ca path
//    // ret.defineCMacro("CURL_CA_PATH", "\"/etc/ssl/certs\"");
//
//    // to make a symbol visible
//    ret.defineCMacro("CURL_EXTERN_SYMBOL", "__attribute__ ((__visibility__ (\"default\"))");
//    // Ensure using CURL_EXTERN_SYMBOL is possible
//    //#ifndef CURL_EXTERN_SYMBOL
//    //ret.defineCMacro("CURL_EXTERN_SYMBOL
//    //#endif
//
//    // Allow SMB to work on Windows
//    // #undef USE_WIN32_CRYPTO
//
//    // Use Windows LDAP implementation
//    // #undef USE_WIN32_LDAP
//
//    // your Entropy Gathering Daemon socket pathname
//    // #undef EGD_SOCKET
//
//    // Define if you want to enable IPv6 support
//    if (!target.isDarwin())
//        ret.defineCMacro("ENABLE_IPV6", "1");
//
//    // Define to 1 if you have the alarm function.
//    ret.defineCMacro("HAVE_ALARM", "1");
//
//    // Define to 1 if you have the <alloca.h> header file.
//    ret.defineCMacro("HAVE_ALLOCA_H", "1");
//
//    // Define to 1 if you have the <arpa/inet.h> header file.
//    ret.defineCMacro("HAVE_ARPA_INET_H", "1");
//
//    // Define to 1 if you have the <arpa/tftp.h> header file.
//    ret.defineCMacro("HAVE_ARPA_TFTP_H", "1");
//
//    // Define to 1 if you have the <assert.h> header file.
//    ret.defineCMacro("HAVE_ASSERT_H", "1");
//
//    // Define to 1 if you have the `basename' function.
//    ret.defineCMacro("HAVE_BASENAME", "1");
//
//    // Define to 1 if bool is an available type.
//    ret.defineCMacro("HAVE_BOOL_T", "1");
//
//    // Define to 1 if you have the __builtin_available function.
//    ret.defineCMacro("HAVE_BUILTIN_AVAILABLE", "1");
//
//    // Define to 1 if you have the clock_gettime function and monotonic timer.
//    ret.defineCMacro("HAVE_CLOCK_GETTIME_MONOTONIC", "1");
//
//    // Define to 1 if you have the `closesocket' function.
//    // #undef HAVE_CLOSESOCKET
//
//    // Define to 1 if you have the `CRYPTO_cleanup_all_ex_data' function.
//    // #undef HAVE_CRYPTO_CLEANUP_ALL_EX_DATA
//
//    // Define to 1 if you have the <dlfcn.h> header file.
//    ret.defineCMacro("HAVE_DLFCN_H", "1");
//
//    // Define to 1 if you have the <errno.h> header file.
//    ret.defineCMacro("HAVE_ERRNO_H", "1");
//
//    // Define to 1 if you have the fcntl function.
//    ret.defineCMacro("HAVE_FCNTL", "1");
//
//    // Define to 1 if you have the <fcntl.h> header file.
//    ret.defineCMacro("HAVE_FCNTL_H", "1");
//
//    // Define to 1 if you have a working fcntl O_NONBLOCK function.
//    ret.defineCMacro("HAVE_FCNTL_O_NONBLOCK", "1");
//
//    // Define to 1 if you have the freeaddrinfo function.
//    ret.defineCMacro("HAVE_FREEADDRINFO", "1");
//
//    // Define to 1 if you have the ftruncate function.
//    ret.defineCMacro("HAVE_FTRUNCATE", "1");
//
//    // Define to 1 if you have a working getaddrinfo function.
//    ret.defineCMacro("HAVE_GETADDRINFO", "1");
//
//    // Define to 1 if you have the `geteuid' function.
//    ret.defineCMacro("HAVE_GETEUID", "1");
//
//    // Define to 1 if you have the `getppid' function.
//    ret.defineCMacro("HAVE_GETPPID", "1");
//
//    // Define to 1 if you have the gethostbyname function.
//    ret.defineCMacro("HAVE_GETHOSTBYNAME", "1");
//
//    // Define to 1 if you have the gethostbyname_r function.
//    if (!target.isDarwin())
//        ret.defineCMacro("HAVE_GETHOSTBYNAME_R", "1");
//
//    // gethostbyname_r() takes 3 args
//    // #undef HAVE_GETHOSTBYNAME_R_3
//
//    // gethostbyname_r() takes 5 args
//    // #undef HAVE_GETHOSTBYNAME_R_5
//
//    // gethostbyname_r() takes 6 args
//    ret.defineCMacro("HAVE_GETHOSTBYNAME_R_6", "1");
//
//    // Define to 1 if you have the gethostname function.
//    ret.defineCMacro("HAVE_GETHOSTNAME", "1");
//
//    // Define to 1 if you have a working getifaddrs function.
//    // #undef HAVE_GETIFADDRS
//
//    // Define to 1 if you have the `getpass_r' function.
//    // #undef HAVE_GETPASS_R
//
//    // Define to 1 if you have the `getppid' function.
//    ret.defineCMacro("HAVE_GETPPID", "1");
//
//    // Define to 1 if you have the `getprotobyname' function.
//    ret.defineCMacro("HAVE_GETPROTOBYNAME", "1");
//
//    // Define to 1 if you have the `getpeername' function.
//    ret.defineCMacro("HAVE_GETPEERNAME", "1");
//
//    // Define to 1 if you have the `getsockname' function.
//    ret.defineCMacro("HAVE_GETSOCKNAME", "1");
//
//    // Define to 1 if you have the `if_nametoindex' function.
//    ret.defineCMacro("HAVE_IF_NAMETOINDEX", "1");
//
//    // Define to 1 if you have the `getpwuid' function.
//    ret.defineCMacro("HAVE_GETPWUID", "1");
//
//    // Define to 1 if you have the `getpwuid_r' function.
//    ret.defineCMacro("HAVE_GETPWUID_R", "1");
//
//    // Define to 1 if you have the `getrlimit' function.
//    ret.defineCMacro("HAVE_GETRLIMIT", "1");
//
//    // Define to 1 if you have the `gettimeofday' function.
//    ret.defineCMacro("HAVE_GETTIMEOFDAY", "1");
//
//    // Define to 1 if you have a working glibc-style strerror_r function.
//    // #undef HAVE_GLIBC_STRERROR_R
//
//    // Define to 1 if you have a working gmtime_r function.
//    ret.defineCMacro("HAVE_GMTIME_R", "1");
//
//    // if you have the gssapi libraries
//    // #undef HAVE_GSSAPI
//
//    // Define to 1 if you have the <gssapi/gssapi_generic.h> header file.
//    // #undef HAVE_GSSAPI_GSSAPI_GENERIC_H
//
//    // Define to 1 if you have the <gssapi/gssapi.h> header file.
//    // #undef HAVE_GSSAPI_GSSAPI_H
//
//    // Define to 1 if you have the <gssapi/gssapi_krb5.h> header file.
//    // #undef HAVE_GSSAPI_GSSAPI_KRB5_H
//
//    // if you have the GNU gssapi libraries
//    // #undef HAVE_GSSGNU
//
//    // if you have the Heimdal gssapi libraries
//    // #undef HAVE_GSSHEIMDAL
//
//    // if you have the MIT gssapi libraries
//    // #undef HAVE_GSSMIT
//
//    // Define to 1 if you have the `idna_strerror' function.
//    // #undef HAVE_IDNA_STRERROR
//
//    // Define to 1 if you have the `idn_free' function.
//    // #undef HAVE_IDN_FREE
//
//    // Define to 1 if you have the <idn-free.h> header file.
//    // #undef HAVE_IDN_FREE_H
//
//    // Define to 1 if you have the <ifaddrs.h> header file.
//    ret.defineCMacro("HAVE_IFADDRS_H", "1");
//
//    // Define to 1 if you have the `inet_addr' function.
//    ret.defineCMacro("HAVE_INET_ADDR", "1");
//
//    // Define to 1 if you have a IPv6 capable working inet_ntop function.
//    // #undef HAVE_INET_NTOP
//
//    // Define to 1 if you have a IPv6 capable working inet_pton function.
//    ret.defineCMacro("HAVE_INET_PTON", "1");
//
//    // Define to 1 if symbol `sa_family_t' exists
//    ret.defineCMacro("HAVE_SA_FAMILY_T", "1");
//
//    // Define to 1 if symbol `ADDRESS_FAMILY' exists
//    // #undef HAVE_ADDRESS_FAMILY
//
//    // Define to 1 if you have the <inttypes.h> header file.
//    ret.defineCMacro("HAVE_INTTYPES_H", "1");
//
//    // Define to 1 if you have the ioctl function.
//    ret.defineCMacro("HAVE_IOCTL", "1");
//
//    // Define to 1 if you have the ioctlsocket function.
//    // #undef HAVE_IOCTLSOCKET
//
//    // Define to 1 if you have the IoctlSocket camel case function.
//    // #undef HAVE_IOCTLSOCKET_CAMEL
//
//    // Define to 1 if you have a working IoctlSocket camel case FIONBIO function.
//
//    // #undef HAVE_IOCTLSOCKET_CAMEL_FIONBIO
//
//    // Define to 1 if you have a working ioctlsocket FIONBIO function.
//    // #undef HAVE_IOCTLSOCKET_FIONBIO
//
//    // Define to 1 if you have a working ioctl FIONBIO function.
//    ret.defineCMacro("HAVE_IOCTL_FIONBIO", "1");
//
//    // Define to 1 if you have a working ioctl SIOCGIFADDR function.
//    ret.defineCMacro("HAVE_IOCTL_SIOCGIFADDR", "1");
//
//    // Define to 1 if you have the <io.h> header file.
//    // #undef HAVE_IO_H
//
//    // if you have the Kerberos4 libraries (including -ldes)
//    // #undef HAVE_KRB4
//
//    // Define to 1 if you have the `krb_get_our_ip_for_realm' function.
//    // #undef HAVE_KRB_GET_OUR_IP_FOR_REALM
//
//    // Define to 1 if you have the <krb.h> header file.
//    // #undef HAVE_KRB_H
//
//    // Define to 1 if you have the lber.h header file.
//    // #undef HAVE_LBER_H
//
//    // Define to 1 if you have the ldapssl.h header file.
//    // #undef HAVE_LDAPSSL_H
//
//    // Define to 1 if you have the ldap.h header file.
//    // #undef HAVE_LDAP_H
//
//    // Use LDAPS implementation
//    // #undef HAVE_LDAP_SSL
//
//    // Define to 1 if you have the ldap_ssl.h header file.
//    // #undef HAVE_LDAP_SSL_H
//
//    // Define to 1 if you have the `ldap_url_parse' function.
//    ret.defineCMacro("HAVE_LDAP_URL_PARSE", "1");
//
//    // Define to 1 if you have the <libgen.h> header file.
//    ret.defineCMacro("HAVE_LIBGEN_H", "1");
//
//    // Define to 1 if you have the `idn2' library (-lidn2).
//    // #undef HAVE_LIBIDN2
//
//    // Define to 1 if you have the idn2.h header file.
//    ret.defineCMacro("HAVE_IDN2_H", "1");
//
//    // Define to 1 if you have the `resolv' library (-lresolv).
//    // #undef HAVE_LIBRESOLV
//
//    // Define to 1 if you have the `resolve' library (-lresolve).
//    // #undef HAVE_LIBRESOLVE
//
//    // Define to 1 if you have the `socket' library (-lsocket).
//    // #undef HAVE_LIBSOCKET
//
//    // if brotli is available
//    // #undef HAVE_BROTLI
//
//    // if zstd is available
//    // #undef HAVE_ZSTD
//
//    // if your compiler supports LL
//    ret.defineCMacro("HAVE_LL", "1");
//
//    // Define to 1 if you have the <locale.h> header file.
//    ret.defineCMacro("HAVE_LOCALE_H", "1");
//
//    // Define to 1 if you have a working localtime_r function.
//    ret.defineCMacro("HAVE_LOCALTIME_R", "1");
//
//    // Define to 1 if the compiler supports the 'long long' data type.
//    ret.defineCMacro("HAVE_LONGLONG", "1");
//
//    // Define to 1 if you have the malloc.h header file.
//    ret.defineCMacro("HAVE_MALLOC_H", "1");
//
//    // Define to 1 if you have the <memory.h> header file.
//    ret.defineCMacro("HAVE_MEMORY_H", "1");
//
//    // Define to 1 if you have the MSG_NOSIGNAL flag.
//    if (!target.isDarwin())
//        ret.defineCMacro("HAVE_MSG_NOSIGNAL", "1");
//
//    // Define to 1 if you have the <netdb.h> header file.
//    ret.defineCMacro("HAVE_NETDB_H", "1");
//
//    // Define to 1 if you have the <netinet/in.h> header file.
//    ret.defineCMacro("HAVE_NETINET_IN_H", "1");
//
//    // Define to 1 if you have the <netinet/tcp.h> header file.
//    ret.defineCMacro("HAVE_NETINET_TCP_H", "1");
//
//    // Define to 1 if you have the <linux/tcp.h> header file.
//    if (target.isLinux())
//        ret.defineCMacro("HAVE_LINUX_TCP_H", "1");
//
//    // Define to 1 if you have the <net/if.h> header file.
//    ret.defineCMacro("HAVE_NET_IF_H", "1");
//
//    // Define to 1 if NI_WITHSCOPEID exists and works.
//    // #undef HAVE_NI_WITHSCOPEID
//
//    // if you have an old MIT gssapi library, lacking GSS_C_NT_HOSTBASED_SERVICE
//    // #undef HAVE_OLD_GSSMIT
//
//    // Define to 1 if you have the <pem.h> header file.
//    // #undef HAVE_PEM_H
//
//    // Define to 1 if you have the `pipe' function.
//    ret.defineCMacro("HAVE_PIPE", "1");
//
//    // Define to 1 if you have a working poll function.
//    ret.defineCMacro("HAVE_POLL", "1");
//
//    // If you have a fine poll
//    ret.defineCMacro("HAVE_POLL_FINE", "1");
//
//    // Define to 1 if you have the <poll.h> header file.
//    ret.defineCMacro("HAVE_POLL_H", "1");
//
//    // Define to 1 if you have a working POSIX-style strerror_r function.
//    ret.defineCMacro("HAVE_POSIX_STRERROR_R", "1");
//
//    // Define to 1 if you have the <pthread.h> header file
//    ret.defineCMacro("HAVE_PTHREAD_H", "1");
//
//    // Define to 1 if you have the <pwd.h> header file.
//    ret.defineCMacro("HAVE_PWD_H", "1");
//
//    // Define to 1 if you have the `RAND_egd' function.
//    // #undef HAVE_RAND_EGD
//
//    // Define to 1 if you have the `RAND_screen' function.
//    // #undef HAVE_RAND_SCREEN
//
//    // Define to 1 if you have the `RAND_status' function.
//    // #undef HAVE_RAND_STATUS
//
//    // Define to 1 if you have the recv function.
//    ret.defineCMacro("HAVE_RECV", "1");
//
//    // Define to 1 if you have the recvfrom function.
//    // #undef HAVE_RECVFROM
//
//    // Define to 1 if you have the select function.
//    ret.defineCMacro("HAVE_SELECT", "1");
//
//    // Define to 1 if you have the send function.
//    ret.defineCMacro("HAVE_SEND", "1");
//
//    // Define to 1 if you have the 'fsetxattr' function.
//    ret.defineCMacro("HAVE_FSETXATTR", "1");
//
//    // fsetxattr() takes 5 args
//    ret.defineCMacro("HAVE_FSETXATTR_5", "1");
//
//    // fsetxattr() takes 6 args
//    // #undef HAVE_FSETXATTR_6
//
//    // Define to 1 if you have the <setjmp.h> header file.
//    ret.defineCMacro("HAVE_SETJMP_H", "1");
//
//    // Define to 1 if you have the `setlocale' function.
//    ret.defineCMacro("HAVE_SETLOCALE", "1");
//
//    // Define to 1 if you have the `setmode' function.
//    // #undef HAVE_SETMODE
//
//    // Define to 1 if you have the `setrlimit' function.
//    ret.defineCMacro("HAVE_SETRLIMIT", "1");
//
//    // Define to 1 if you have the setsockopt function.
//    ret.defineCMacro("HAVE_SETSOCKOPT", "1");
//
//    // Define to 1 if you have a working setsockopt SO_NONBLOCK function.
//    // #undef HAVE_SETSOCKOPT_SO_NONBLOCK
//
//    // Define to 1 if you have the sigaction function.
//    ret.defineCMacro("HAVE_SIGACTION", "1");
//
//    // Define to 1 if you have the siginterrupt function.
//    ret.defineCMacro("HAVE_SIGINTERRUPT", "1");
//
//    // Define to 1 if you have the signal function.
//    ret.defineCMacro("HAVE_SIGNAL", "1");
//
//    // Define to 1 if you have the <signal.h> header file.
//    ret.defineCMacro("HAVE_SIGNAL_H", "1");
//
//    // Define to 1 if you have the sigsetjmp function or macro.
//    ret.defineCMacro("HAVE_SIGSETJMP", "1");
//
//    // Define to 1 if struct sockaddr_in6 has the sin6_scope_id member
//    ret.defineCMacro("HAVE_SOCKADDR_IN6_SIN6_SCOPE_ID", "1");
//
//    // Define to 1 if you have the `socket' function.
//    ret.defineCMacro("HAVE_SOCKET", "1");
//
//    // Define to 1 if you have the <stdbool.h> header file.
//    ret.defineCMacro("HAVE_STDBOOL_H", "1");
//
//    // Define to 1 if you have the <stdint.h> header file.
//    ret.defineCMacro("HAVE_STDINT_H", "1");
//
//    // Define to 1 if you have the <stdio.h> header file.
//    ret.defineCMacro("HAVE_STDIO_H", "1");
//
//    // Define to 1 if you have the <stdlib.h> header file.
//    ret.defineCMacro("HAVE_STDLIB_H", "1");
//
//    // Define to 1 if you have the strcasecmp function.
//    ret.defineCMacro("HAVE_STRCASECMP", "1");
//
//    // Define to 1 if you have the strcasestr function.
//    // #undef HAVE_STRCASESTR
//
//    // Define to 1 if you have the strcmpi function.
//    // #undef HAVE_STRCMPI
//
//    // Define to 1 if you have the strdup function.
//    ret.defineCMacro("HAVE_STRDUP", "1");
//
//    // Define to 1 if you have the strerror_r function.
//    ret.defineCMacro("HAVE_STRERROR_R", "1");
//
//    // Define to 1 if you have the stricmp function.
//    // #undef HAVE_STRICMP
//
//    // Define to 1 if you have the <strings.h> header file.
//    ret.defineCMacro("HAVE_STRINGS_H", "1");
//
//    // Define to 1 if you have the <string.h> header file.
//    ret.defineCMacro("HAVE_STRING_H", "1");
//
//    // Define to 1 if you have the strncmpi function.
//    // #undef HAVE_STRNCMPI
//
//    // Define to 1 if you have the strnicmp function.
//    // #undef HAVE_STRNICMP
//
//    // Define to 1 if you have the <stropts.h> header file.
//    // #undef HAVE_STROPTS_H
//
//    // Define to 1 if you have the strstr function.
//    ret.defineCMacro("HAVE_STRSTR", "1");
//
//    // Define to 1 if you have the strtok_r function.
//    ret.defineCMacro("HAVE_STRTOK_R", "1");
//
//    // Define to 1 if you have the strtoll function.
//    ret.defineCMacro("HAVE_STRTOLL", "1");
//
//    // if struct sockaddr_storage is defined
//    ret.defineCMacro("HAVE_STRUCT_SOCKADDR_STORAGE", "1");
//
//    // Define to 1 if you have the timeval struct.
//    ret.defineCMacro("HAVE_STRUCT_TIMEVAL", "1");
//
//    // Define to 1 if you have the <sys/filio.h> header file.
//    // #undef HAVE_SYS_FILIO_H
//
//    // Define to 1 if you have the <sys/ioctl.h> header file.
//    ret.defineCMacro("HAVE_SYS_IOCTL_H", "1");
//
//    // Define to 1 if you have the <sys/param.h> header file.
//    ret.defineCMacro("HAVE_SYS_PARAM_H", "1");
//
//    // Define to 1 if you have the <sys/poll.h> header file.
//    ret.defineCMacro("HAVE_SYS_POLL_H", "1");
//
//    // Define to 1 if you have the <sys/resource.h> header file.
//    ret.defineCMacro("HAVE_SYS_RESOURCE_H", "1");
//
//    // Define to 1 if you have the <sys/select.h> header file.
//    ret.defineCMacro("HAVE_SYS_SELECT_H", "1");
//
//    // Define to 1 if you have the <sys/socket.h> header file.
//    ret.defineCMacro("HAVE_SYS_SOCKET_H", "1");
//
//    // Define to 1 if you have the <sys/sockio.h> header file.
//    // #undef HAVE_SYS_SOCKIO_H
//
//    // Define to 1 if you have the <sys/stat.h> header file.
//    ret.defineCMacro("HAVE_SYS_STAT_H", "1");
//
//    // Define to 1 if you have the <sys/time.h> header file.
//    ret.defineCMacro("HAVE_SYS_TIME_H", "1");
//
//    // Define to 1 if you have the <sys/types.h> header file.
//    ret.defineCMacro("HAVE_SYS_TYPES_H", "1");
//
//    // Define to 1 if you have the <sys/uio.h> header file.
//    ret.defineCMacro("HAVE_SYS_UIO_H", "1");
//
//    // Define to 1 if you have the <sys/un.h> header file.
//    ret.defineCMacro("HAVE_SYS_UN_H", "1");
//
//    // Define to 1 if you have the <sys/utime.h> header file.
//    // #undef HAVE_SYS_UTIME_H
//
//    // Define to 1 if you have the <termios.h> header file.
//    ret.defineCMacro("HAVE_TERMIOS_H", "1");
//
//    // Define to 1 if you have the <termio.h> header file.
//    ret.defineCMacro("HAVE_TERMIO_H", "1");
//
//    // Define to 1 if you have the <time.h> header file.
//    ret.defineCMacro("HAVE_TIME_H", "1");
//
//    // Define to 1 if you have the <tld.h> header file.
//    // #undef HAVE_TLD_H
//
//    // Define to 1 if you have the `tld_strerror' function.
//    // #undef HAVE_TLD_STRERROR
//
//    // Define to 1 if you have the `uname' function.
//    ret.defineCMacro("HAVE_UNAME", "1");
//
//    // Define to 1 if you have the <unistd.h> header file.
//    ret.defineCMacro("HAVE_UNISTD_H", "1");
//
//    // Define to 1 if you have the `utime' function.
//    ret.defineCMacro("HAVE_UTIME", "1");
//
//    // Define to 1 if you have the `utimes' function.
//    ret.defineCMacro("HAVE_UTIMES", "1");
//
//    // Define to 1 if you have the <utime.h> header file.
//    ret.defineCMacro("HAVE_UTIME_H", "1");
//
//    // Define to 1 if compiler supports C99 variadic macro style.
//    ret.defineCMacro("HAVE_VARIADIC_MACROS_C99", "1");
//
//    // Define to 1 if compiler supports old gcc variadic macro style.
//    ret.defineCMacro("HAVE_VARIADIC_MACROS_GCC", "1");
//
//    // Define to 1 if you have the winber.h header file.
//    // #undef HAVE_WINBER_H
//
//    // Define to 1 if you have the windows.h header file.
//    // #undef HAVE_WINDOWS_H
//
//    // Define to 1 if you have the winldap.h header file.
//    // #undef HAVE_WINLDAP_H
//
//    // Define to 1 if you have the winsock2.h header file.
//    // #undef HAVE_WINSOCK2_H
//
//    // Define this symbol if your OS supports changing the contents of argv
//    // #undef HAVE_WRITABLE_ARGV
//
//    // Define to 1 if you have the writev function.
//    // #undef HAVE_WRITEV
//
//    // Define to 1 if you have the ws2tcpip.h header file.
//    // #undef HAVE_WS2TCPIP_H
//
//    // Define to 1 if you have the <x509.h> header file.
//    // #undef HAVE_X509_H
//
//    // Define if you have the <process.h> header file.
//    // #undef HAVE_PROCESS_H
//
//    // Define to the sub-directory in which libtool stores uninstalled libraries.
//
//    // #undef LT_OBJDIR
//
//    // If you lack a fine basename() prototype
//    // #undef NEED_BASENAME_PROTO
//
//    // Define to 1 if you need the lber.h header file even with ldap.h
//    // #undef NEED_LBER_H
//
//    // Define to 1 if you need the malloc.h header file even with stdlib.h
//    // #undef NEED_MALLOC_H
//
//    // Define to 1 if _REENTRANT preprocessor symbol must be defined.
//    // #undef NEED_REENTRANT
//
//    // cpu-machine-OS
//    ret.defineCMacro("OS", "\"Linux\"");
//
//    // Name of package
//    // #undef PACKAGE
//
//    // Define to the address where bug reports for this package should be sent.
//    // #undef PACKAGE_BUGREPORT
//
//    // Define to the full name of this package.
//    // #undef PACKAGE_NAME
//
//    // Define to the full name and version of this package.
//    // #undef PACKAGE_STRING
//
//    // Define to the one symbol short name of this package.
//    // #undef PACKAGE_TARNAME
//
//    // Define to the version of this package.
//    // #undef PACKAGE_VERSION
//
//    // a suitable file to read random data from
//    ret.defineCMacro("RANDOM_FILE", "\"/dev/urandom\"");
//
//    // Define to the type of arg 1 for recvfrom.
//    // #undef RECVFROM_TYPE_ARG1
//
//    // Define to the type pointed by arg 2 for recvfrom.
//    // #undef RECVFROM_TYPE_ARG2
//
//    // Define to 1 if the type pointed by arg 2 for recvfrom is void.
//    // #undef RECVFROM_TYPE_ARG2_IS_VOID
//
//    // Define to the type of arg 3 for recvfrom.
//    // #undef RECVFROM_TYPE_ARG3
//
//    // Define to the type of arg 4 for recvfrom.
//    // #undef RECVFROM_TYPE_ARG4
//
//    // Define to the type pointed by arg 5 for recvfrom.
//    // #undef RECVFROM_TYPE_ARG5
//
//    // Define to 1 if the type pointed by arg 5 for recvfrom is void.
//    // #undef RECVFROM_TYPE_ARG5_IS_VOID
//
//    // Define to the type pointed by arg 6 for recvfrom.
//    // #undef RECVFROM_TYPE_ARG6
//
//    // Define to 1 if the type pointed by arg 6 for recvfrom is void.
//    // #undef RECVFROM_TYPE_ARG6_IS_VOID
//
//    // Define to the function return type for recvfrom.
//    // #undef RECVFROM_TYPE_RETV
//
//    // Define to the type of arg 1 for recv.
//    ret.defineCMacro("RECV_TYPE_ARG1", "int");
//
//    // Define to the type of arg 2 for recv.
//    ret.defineCMacro("RECV_TYPE_ARG2", "void *");
//
//    // Define to the type of arg 3 for recv.
//    ret.defineCMacro("RECV_TYPE_ARG3", "size_t");
//
//    // Define to the type of arg 4 for recv.
//    ret.defineCMacro("RECV_TYPE_ARG4", "int");
//
//    // Define to the function return type for recv.
//    ret.defineCMacro("RECV_TYPE_RETV", "ssize_t");
//
//    // Define to the type qualifier of arg 5 for select.
//    // #undef SELECT_QUAL_ARG5
//
//    // Define to the type of arg 1 for select.
//    // #undef SELECT_TYPE_ARG1
//
//    // Define to the type of args 2, 3 and 4 for select.
//    // #undef SELECT_TYPE_ARG234
//
//    // Define to the type of arg 5 for select.
//    // #undef SELECT_TYPE_ARG5
//
//    // Define to the function return type for select.
//    // #undef SELECT_TYPE_RETV
//
//    // Define to the type qualifier of arg 2 for send.
//    ret.defineCMacro("SEND_QUAL_ARG2", "const");
//
//    // Define to the type of arg 1 for send.
//    ret.defineCMacro("SEND_TYPE_ARG1", "int");
//
//    // Define to the type of arg 2 for send.
//    ret.defineCMacro("SEND_TYPE_ARG2", "void *");
//
//    // Define to the type of arg 3 for send.
//    ret.defineCMacro("SEND_TYPE_ARG3", "size_t");
//
//    // Define to the type of arg 4 for send.
//    ret.defineCMacro("SEND_TYPE_ARG4", "int");
//
//    // Define to the function return type for send.
//    ret.defineCMacro("SEND_TYPE_RETV", "ssize_t");
//
//    // Note: SIZEOF_* variables are fetched with CMake through check_type_size().
//    // As per CMake documentation on CheckTypeSize, C preprocessor code is
//    // generated by CMake into SIZEOF_*_CODE. This is what we use in the
//    // following statements.
//    //
//    // Reference: https://cmake.org/cmake/help/latest/module/CheckTypeSize.html
//
//    // The size of `int', as computed by sizeof.
//    ret.defineCMacro("SIZEOF_INT", "4");
//
//    // The size of `short', as computed by sizeof.
//    ret.defineCMacro("SIZEOF_SHORT", "2");
//
//    // The size of `long', as computed by sizeof.
//    ret.defineCMacro("SIZEOF_LONG", "8");
//
//    // The size of `off_t', as computed by sizeof.
//    ret.defineCMacro("SIZEOF_OFF_T", "8");
//
//    // The size of `curl_off_t', as computed by sizeof.
//    ret.defineCMacro("SIZEOF_CURL_OFF_T", "8");
//
//    // The size of `size_t', as computed by sizeof.
//    ret.defineCMacro("SIZEOF_SIZE_T", "8");
//
//    // The size of `time_t', as computed by sizeof.
//    ret.defineCMacro("SIZEOF_TIME_T", "8");
//
//    // Define to 1 if you have the ANSI C header files.
//    ret.defineCMacro("STDC_HEADERS", "1");
//
//    // Define to the type of arg 3 for strerror_r.
//    // #undef STRERROR_R_TYPE_ARG3
//
//    // Define to 1 if you can safely include both <sys/time.h> and <time.h>.
//    ret.defineCMacro("TIME_WITH_SYS_TIME", "1");
//
//    // Define if you want to enable c-ares support
//    // #undef USE_ARES
//
//    // Define if you want to enable POSIX threaded DNS lookup
//    ret.defineCMacro("USE_THREADS_POSIX", "1");
//
//    // if libSSH2 is in use
//    ret.defineCMacro("USE_LIBSSH2", "1");
//
//    // If you want to build curl with the built-in manual
//    // #undef USE_MANUAL
//
//    // if NSS is enabled
//    // #undef USE_NSS
//
//    // if you have the PK11_CreateManagedGenericObject function
//    // #undef HAVE_PK11_CREATEMANAGEDGENERICOBJECT
//
//    // if you want to use OpenLDAP code instead of legacy ldap implementation
//    // #undef USE_OPENLDAP
//
//    // to enable NGHTTP2
//    // #undef USE_NGHTTP2
//
//    // to enable NGTCP2
//    // #undef USE_NGTCP2
//
//    // to enable NGHTTP3
//    // #undef USE_NGHTTP3
//
//    // to enable quiche
//    // #undef USE_QUICHE
//
//    // Define to 1 if you have the quiche_conn_set_qlog_fd function.
//    // #undef HAVE_QUICHE_CONN_SET_QLOG_FD
//
//    // if Unix domain sockets are enabled
//    ret.defineCMacro("USE_UNIX_SOCKETS", null);
//
//    // Define to 1 if you are building a Windows target with large file support.
//    // #undef USE_WIN32_LARGE_FILES
//
//    // to enable SSPI support
//    // #undef USE_WINDOWS_SSPI
//
//    // to enable Windows SSL
//    // #undef USE_SCHANNEL
//
//    // enable multiple SSL backends
//    // #undef CURL_WITH_MULTI_SSL
//
//    // Define to 1 if using yaSSL in OpenSSL compatibility mode.
//    // #undef USE_YASSLEMUL
//
//    // Version number of package
//    // #undef VERSION
//
//    // Define to 1 if OS is AIX.
//    //#ifndef _ALL_SOURCE
//    //#  undef _ALL_SOURCE
//    //#endif
//
//    // Number of bits in a file offset, on hosts where this is settable.
//    ret.defineCMacro("_FILE_OFFSET_BITS", "64");
//
//    // Define for large files, on AIX-style hosts.
//    // #undef _LARGE_FILES
//
//    // define this if you need it to compile thread-safe code
//    // #undef _THREAD_SAFE
//
//    // Define to empty if `const' does not conform to ANSI C.
//    // #undef const
//
//    // Type to use in place of in_addr_t when system does not provide it.
//    // #undef in_addr_t
//
//    // Define to `__inline__' or `__inline' if that's what the C compiler
//    // calls it, or to nothing if 'inline' is not supported under any name.
//    //#ifndef __cplusplus
//    //#undef inline
//    //#endif
//
//    // Define to `unsigned int' if <sys/types.h> does not define.
//    // #undef size_t
//
//    // the signed version of size_t
//    // #undef ssize_t
//
//    // Define to 1 if you have the mach_absolute_time function.
//    // #undef HAVE_MACH_ABSOLUTE_TIME
//
//    // to enable Windows IDN
//    // #undef USE_WIN32_IDN
//
//    // to make the compiler know the prototypes of Windows IDN APIs
//    // #undef WANT_IDN_PROTOTYPES
//
//    return Library{ .step = ret, .exported_defines = exported_defines.toOwnedSlice() };

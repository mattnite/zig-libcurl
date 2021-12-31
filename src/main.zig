const std = @import("std");
const testing = std.testing;

pub const c = @cImport({
    @cInclude("curl/curl.h");
});

pub fn globalInit() Error!void {
    return tryCurl(c.curl_global_init(c.CURL_GLOBAL_ALL));
}

pub fn globalCleanup() void {
    c.curl_global_cleanup();
}

pub const XferInfoFn = c.curl_xferinfo_callback;
pub const WriteFn = c.curl_write_callback;

pub const Easy = opaque {
    pub fn init() Error!*Easy {
        return @ptrCast(?*Easy, c.curl_easy_init()) orelse error.FailedInit;
    }

    pub fn cleanup(self: *Easy) void {
        c.curl_easy_cleanup(self);
    }

    pub fn setUrl(self: *Easy, url: [:0]const u8) Error!void {
        return tryCurl(c.curl_easy_setopt(self, c.CURLOPT_URL, url.ptr));
    }

    pub fn setFollowLocation(self: *Easy, val: bool) Error!void {
        return tryCurl(c.curl_easy_setopt(self, c.CURLOPT_FOLLOWLOCATION, @as(c_ulong, if (val) 1 else 0)));
    }

    pub fn setVerbose(self: *Easy, val: bool) Error!void {
        return tryCurl(c.curl_easy_setopt(self, c.CURLOPT_VERBOSE, @as(c_ulong, if (val) 1 else 0)));
    }

    pub fn setSslVerifyPeer(self: *Easy, val: bool) Error!void {
        return tryCurl(c.curl_easy_setopt(self, c.CURLOPT_SSL_VERIFYPEER, @as(c_ulong, if (val) 1 else 0)));
    }

    pub fn setWriteFn(self: *Easy, write: WriteFn) Error!void {
        return tryCurl(c.curl_easy_setopt(self, c.CURLOPT_WRITEFUNCTION, write));
    }

    pub fn setWriteData(self: *Easy, data: anyopaque) Error!void {
        return tryCurl(c.curl_easy_setopt(self, c.CURLOPT_WRITEDATA, data));
    }

    pub fn setXferInfoFn(self: *Easy, xfer: XferInfoFn) Error!void {
        return tryCurl(c.curl_easy_setopt(self, c.CURLOPT_XFERINFOFUNCTION, xfer));
    }

    pub fn setXferInfoData(self: *Easy, data: anyopaque) Error!void {
        return tryCurl(c.curl_easy_setopt(self, c.CURLOPT_XFERINFODATA, data));
    }

    pub fn setErrorBuffer(self: *Easy, data: *[c.CURL_ERROR_SIZE]u8) Error!void {
        return tryCurl(c.curl_easy_setopt(self, c.CURLOPT_XFERINFODATA, data));
    }

    pub fn perform(self: *Easy) Error!void {
        return tryCurl(c.curl_easy_perform(self));
    }

    pub fn getResponseCode(self: *Easy) Error!isize {
        var code: isize = undefined;
        try tryCurl(c.curl_easy_getinfo(self, c.CURLINFO_RESPONSE_CODE, &code));
        return code;
    }
};

fn emptyWrite(ptr: ?[*]u8, size: usize, nmemb: usize, data: ?*anyopaque) callconv(.C) usize {
    _ = ptr;
    _ = data;
    _ = size;

    return nmemb;
}

test "https put" {
    try globalInit();
    defer globalCleanup();

    var error_buf: [c.CURL_ERROR_SIZE]u8 = undefined;

    var easy = try Easy.init();
    defer easy.cleanup();

    try easy.setUrl("https://example.com");
    try easy.setSslVerifyPeer(false);
    try easy.setWriteFn(emptyWrite);
    try easy.setErrorBuffer(&error_buf);
    try easy.setVerbose(true);
    easy.perform() catch |err| {
        std.log.err("{s}", .{@ptrCast([*:0]const u8, &error_buf)});
        return err;
    };
    const code = try easy.getResponseCode();

    try std.testing.expectEqual(@as(isize, 200), code);
}

pub const Error = error{
    UnsupportedProtocol,
    FailedInit,
    UrlMalformat,
    NotBuiltIn,
    CouldntResolveProxy,
    CouldntResolveHost,
    CounldntConnect,
    WeirdServerReply,
    RemoteAccessDenied,
    FtpAcceptFailed,
    FtpWeirdPassReply,
    FtpAcceptTimeout,
    FtpWeirdPasvReply,
    FtpWeird227Format,
    FtpCantGetHost,
    Http2,
    FtpCouldntSetType,
    PartialFile,
    FtpCouldntRetrFile,
    Obsolete20,
    QuoteError,
    HttpReturnedError,
    WriteError,
    Obsolete24,
    UploadFailed,
    ReadError,
    OutOfMemory,
    OperationTimeout,
    Obsolete29,
    FtpPortFailed,
    FtpCouldntUseRest,
    Obsolete32,
    RangeError,
    HttpPostError,
    SslConnectError,
    BadDownloadResume,
    FileCouldntReadFile,
    LdapCannotBind,
    LdapSearchFailed,
    Obsolete40,
    FunctionNotFound,
    AbortByCallback,
    BadFunctionArgument,
    Obsolete44,
    InterfaceFailed,
    Obsolete46,
    TooManyRedirects,
    UnknownOption,
    SetoptOptionSyntax,
    Obsolete50,
    Obsolete51,
    GotNothing,
    SslEngineNotfound,
    SslEngineSetfailed,
    SendError,
    RecvError,
    Obsolete57,
    SslCertproblem,
    SslCipher,
    PeerFailedVerification,
    BadContentEncoding,
    LdapInvalidUrl,
    FilesizeExceeded,
    UseSslFailed,
    SendFailRewind,
    SslEngineInitfailed,
    LoginDenied,
    TftpNotfound,
    TftpPerm,
    RemoteDiskFull,
    TftpIllegal,
    Tftp_Unknownid,
    RemoteFileExists,
    TftpNosuchuser,
    ConvFailed,
    ConvReqd,
    SslCacertBadfile,
    RemoteFileNotFound,
    Ssh,
    SslShutdownFailed,
    Again,
    SslCrlBadfile,
    SslIssuerError,
    FtpPretFailed,
    RtspCseqError,
    RtspSessionError,
    FtpBadFileList,
    ChunkFailed,
    NoConnectionAvailable,
    SslPinnedpubkeynotmatch,
    SslInvalidcertstatus,
    Http2Stream,
    RecursiveApiCall,
    AuthError,
    Http3,
    QuicConnectError,
    Proxy,
    SslClientCert,
    UnknownErrorCode,
};

fn tryCurl(code: c.CURLcode) Error!void {
    if (code != c.CURLE_OK)
        return errorFromCurl(code);
}

fn errorFromCurl(code: c.CURLcode) Error {
    return switch (code) {
        c.CURLE_UNSUPPORTED_PROTOCOL => error.UnsupportedProtocol,
        c.CURLE_FAILED_INIT => error.FailedInit,
        c.CURLE_URL_MALFORMAT => error.UrlMalformat,
        c.CURLE_NOT_BUILT_IN => error.NotBuiltIn,
        c.CURLE_COULDNT_RESOLVE_PROXY => error.CouldntResolveProxy,
        c.CURLE_COULDNT_RESOLVE_HOST => error.CouldntResolveHost,
        c.CURLE_COULDNT_CONNECT => error.CounldntConnect,
        c.CURLE_WEIRD_SERVER_REPLY => error.WeirdServerReply,
        c.CURLE_REMOTE_ACCESS_DENIED => error.RemoteAccessDenied,
        c.CURLE_FTP_ACCEPT_FAILED => error.FtpAcceptFailed,
        c.CURLE_FTP_WEIRD_PASS_REPLY => error.FtpWeirdPassReply,
        c.CURLE_FTP_ACCEPT_TIMEOUT => error.FtpAcceptTimeout,
        c.CURLE_FTP_WEIRD_PASV_REPLY => error.FtpWeirdPasvReply,
        c.CURLE_FTP_WEIRD_227_FORMAT => error.FtpWeird227Format,
        c.CURLE_FTP_CANT_GET_HOST => error.FtpCantGetHost,
        c.CURLE_HTTP2 => error.Http2,
        c.CURLE_FTP_COULDNT_SET_TYPE => error.FtpCouldntSetType,
        c.CURLE_PARTIAL_FILE => error.PartialFile,
        c.CURLE_FTP_COULDNT_RETR_FILE => error.FtpCouldntRetrFile,
        c.CURLE_OBSOLETE20 => error.Obsolete20,
        c.CURLE_QUOTE_ERROR => error.QuoteError,
        c.CURLE_HTTP_RETURNED_ERROR => error.HttpReturnedError,
        c.CURLE_WRITE_ERROR => error.WriteError,
        c.CURLE_OBSOLETE24 => error.Obsolete24,
        c.CURLE_UPLOAD_FAILED => error.UploadFailed,
        c.CURLE_READ_ERROR => error.ReadError,
        c.CURLE_OUT_OF_MEMORY => error.OutOfMemory,
        c.CURLE_OPERATION_TIMEDOUT => error.OperationTimeout,
        c.CURLE_OBSOLETE29 => error.Obsolete29,
        c.CURLE_FTP_PORT_FAILED => error.FtpPortFailed,
        c.CURLE_FTP_COULDNT_USE_REST => error.FtpCouldntUseRest,
        c.CURLE_OBSOLETE32 => error.Obsolete32,
        c.CURLE_RANGE_ERROR => error.RangeError,
        c.CURLE_HTTP_POST_ERROR => error.HttpPostError,
        c.CURLE_SSL_CONNECT_ERROR => error.SslConnectError,
        c.CURLE_BAD_DOWNLOAD_RESUME => error.BadDownloadResume,
        c.CURLE_FILE_COULDNT_READ_FILE => error.FileCouldntReadFile,
        c.CURLE_LDAP_CANNOT_BIND => error.LdapCannotBind,
        c.CURLE_LDAP_SEARCH_FAILED => error.LdapSearchFailed,
        c.CURLE_OBSOLETE40 => error.Obsolete40,
        c.CURLE_FUNCTION_NOT_FOUND => error.FunctionNotFound,
        c.CURLE_ABORTED_BY_CALLBACK => error.AbortByCallback,
        c.CURLE_BAD_FUNCTION_ARGUMENT => error.BadFunctionArgument,
        c.CURLE_OBSOLETE44 => error.Obsolete44,
        c.CURLE_INTERFACE_FAILED => error.InterfaceFailed,
        c.CURLE_OBSOLETE46 => error.Obsolete46,
        c.CURLE_TOO_MANY_REDIRECTS => error.TooManyRedirects,
        c.CURLE_UNKNOWN_OPTION => error.UnknownOption,
        c.CURLE_SETOPT_OPTION_SYNTAX => error.SetoptOptionSyntax,
        c.CURLE_OBSOLETE50 => error.Obsolete50,
        c.CURLE_OBSOLETE51 => error.Obsolete51,
        c.CURLE_GOT_NOTHING => error.GotNothing,
        c.CURLE_SSL_ENGINE_NOTFOUND => error.SslEngineNotfound,
        c.CURLE_SSL_ENGINE_SETFAILED => error.SslEngineSetfailed,
        c.CURLE_SEND_ERROR => error.SendError,
        c.CURLE_RECV_ERROR => error.RecvError,
        c.CURLE_OBSOLETE57 => error.Obsolete57,
        c.CURLE_SSL_CERTPROBLEM => error.SslCertproblem,
        c.CURLE_SSL_CIPHER => error.SslCipher,
        c.CURLE_PEER_FAILED_VERIFICATION => error.PeerFailedVerification,
        c.CURLE_BAD_CONTENT_ENCODING => error.BadContentEncoding,
        c.CURLE_LDAP_INVALID_URL => error.LdapInvalidUrl,
        c.CURLE_FILESIZE_EXCEEDED => error.FilesizeExceeded,
        c.CURLE_USE_SSL_FAILED => error.UseSslFailed,
        c.CURLE_SEND_FAIL_REWIND => error.SendFailRewind,
        c.CURLE_SSL_ENGINE_INITFAILED => error.SslEngineInitfailed,
        c.CURLE_LOGIN_DENIED => error.LoginDenied,
        c.CURLE_TFTP_NOTFOUND => error.TftpNotfound,
        c.CURLE_TFTP_PERM => error.TftpPerm,
        c.CURLE_REMOTE_DISK_FULL => error.RemoteDiskFull,
        c.CURLE_TFTP_ILLEGAL => error.TftpIllegal,
        c.CURLE_TFTP_UNKNOWNID => error.Tftp_Unknownid,
        c.CURLE_REMOTE_FILE_EXISTS => error.RemoteFileExists,
        c.CURLE_TFTP_NOSUCHUSER => error.TftpNosuchuser,
        c.CURLE_CONV_FAILED => error.ConvFailed,
        c.CURLE_CONV_REQD => error.ConvReqd,
        c.CURLE_SSL_CACERT_BADFILE => error.SslCacertBadfile,
        c.CURLE_REMOTE_FILE_NOT_FOUND => error.RemoteFileNotFound,
        c.CURLE_SSH => error.Ssh,
        c.CURLE_SSL_SHUTDOWN_FAILED => error.SslShutdownFailed,
        c.CURLE_AGAIN => error.Again,
        c.CURLE_SSL_CRL_BADFILE => error.SslCrlBadfile,
        c.CURLE_SSL_ISSUER_ERROR => error.SslIssuerError,
        c.CURLE_FTP_PRET_FAILED => error.FtpPretFailed,
        c.CURLE_RTSP_CSEQ_ERROR => error.RtspCseqError,
        c.CURLE_RTSP_SESSION_ERROR => error.RtspSessionError,
        c.CURLE_FTP_BAD_FILE_LIST => error.FtpBadFileList,
        c.CURLE_CHUNK_FAILED => error.ChunkFailed,
        c.CURLE_NO_CONNECTION_AVAILABLE => error.NoConnectionAvailable,
        c.CURLE_SSL_PINNEDPUBKEYNOTMATCH => error.SslPinnedpubkeynotmatch,
        c.CURLE_SSL_INVALIDCERTSTATUS => error.SslInvalidcertstatus,
        c.CURLE_HTTP2_STREAM => error.Http2Stream,
        c.CURLE_RECURSIVE_API_CALL => error.RecursiveApiCall,
        c.CURLE_AUTH_ERROR => error.AuthError,
        c.CURLE_HTTP3 => error.Http3,
        c.CURLE_QUIC_CONNECT_ERROR => error.QuicConnectError,
        c.CURLE_PROXY => error.Proxy,
        c.CURLE_SSL_CLIENTCERT => error.SslClientCert,

        else => blk: {
            std.debug.assert(false);
            break :blk error.UnknownErrorCode;
        },
    };
}

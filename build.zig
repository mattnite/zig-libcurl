const std = @import("std");
const libcurl = @import("libcurl.zig");
const mbedtls = @import("mbedtls");
const libssh2 = @import("libssh2");
const zlib = @import("zlib");

pub fn build(b: *std.build.Builder) void {
    const target = b.standardTargetOptions(.{});
    const mode = b.standardReleaseOptions();

    const z = zlib.create(b, target, mode);
    const tls = mbedtls.create(b, target, mode);
    const ssh2 = libssh2.create(b, target, mode);
    ssh2.addIncludeDir(mbedtls.include_dir);
    const curl = libcurl.create(b, target, mode);
    curl.linkLibrary(z);
    curl.addIncludeDir(zlib.include_dir);
    curl.linkLibrary(ssh2);
    curl.addIncludeDir(libssh2.include_dir);
    curl.linkLibrary(tls);
    curl.addIncludeDir(mbedtls.include_dir);
    curl.install();

    const http_put = b.addExecutable("http-put", null);
    http_put.setTarget(target);
    http_put.setBuildMode(mode);
    http_put.addCSourceFile("examples/http-put.c", &.{});
    http_put.linkLibrary(curl);
    http_put.addIncludeDir(libcurl.include_dir);
    //mbedtls.link(http_put);
    http_put.linkLibrary(tls);
    http_put.linkLibrary(ssh2);
    http_put.linkLibrary(z);
    http_put.install();
}

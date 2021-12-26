const std = @import("std");
const libcurl = @import("libcurl.zig");
const mbedtls = @import("mbedtls");
const libssh2 = @import("libssh2");
const zlib = @import("zlib");

pub fn build(b: *std.build.Builder) !void {
    const target = b.standardTargetOptions(.{});
    const mode = b.standardReleaseOptions();

    const z = zlib.create(b, target, mode);
    const tls = mbedtls.create(b, target, mode);
    const ssh2 = libssh2.create(b, target, mode, .{
        .mbedtls_include_dir = mbedtls.include_dir,
    });
    const curl = try libcurl.create(b, target, mode, .{
        .zlib_include_dir = zlib.include_dir,
        .libssh2_include_dir = libssh2.include_dir,
        .mbedtls_include_dir = mbedtls.include_dir,
    });
    // TODO: combine these static libs into one maybe?
    //curl.linkLibrary(z);
    //curl.linkLibrary(ssh2);
    //curl.linkLibrary(tls);
    curl.step.install();

    const tests = b.addTest("src/main.zig");
    tests.setBuildMode(mode);
    tests.setTarget(target);
    curl.link(tests);
    tests.linkLibrary(tls);
    tests.linkLibrary(ssh2);
    tests.linkLibrary(z);

    const test_step = b.step("test", "Run tests");
    test_step.dependOn(&tests.step);
}

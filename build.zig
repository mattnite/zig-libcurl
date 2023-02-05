const std = @import("std");

const build_pkgs = @import("deps.zig").build_pkgs;

const libcurl = @import("libcurl.zig");
const mbedtls = build_pkgs.mbedtls;
const libssh2 = build_pkgs.libssh2;
const zlib = build_pkgs.zlib;

pub fn build(b: *std.build.Builder) !void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    const z = zlib.create(b, target, optimize);
    const tls = mbedtls.create(b, target, optimize);
    const ssh2 = libssh2.create(b, target, optimize);
    tls.link(ssh2.step);

    const curl = try libcurl.create(b, target, optimize);
    ssh2.link(curl.step);
    tls.link(curl.step);
    z.link(curl.step, .{});
    curl.step.install();

    const tests = b.addTest(.{
        .root_source_file = .{ .path = "src/main.zig" },
        .target = target,
        .optimize = optimize,
    });
    curl.link(tests, .{});
    z.link(tests, .{});
    tls.link(tests);
    ssh2.link(tests);

    const test_step = b.step("test", "Run tests");
    test_step.dependOn(&tests.step);
}

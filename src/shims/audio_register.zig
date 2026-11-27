//! Holds the extracted Core.Metadata pack bytes for the future native RPF mount.
//! No engine code is patched and no device constructor is invoked here.

var g_rpf: ?[]const u8 = null;

pub fn init(rpf: []const u8, _: []const u8) void {
    g_rpf = rpf;
}

//! Minimal real GameInput backend for Linux.
//!
//! When `/dev/input/event*` devices are readable, they are opened and polled by
//! a host reader thread.  Key/mouse state is exposed through IGameInputReading;
//! existing devices are delivered through RegisterDeviceCallback.  When no
//! device is available, registration returns GAMEINPUT_E_DEVICE_NOT_FOUND and
//! CreateDispatcher returns E_NOTIMPL: no callback is ever claimed that cannot
//! fire.  Reading callbacks are not implemented and say so.

const std = @import("std");
const builtin = @import("builtin");

const win: std.builtin.CallingConvention = .{ .x86_64_win = .{} };
const HRESULT = i32;
const S_OK: HRESULT = 0;
const E_INVALIDARG: HRESULT = @bitCast(@as(u32, 0x8007_0057));
const E_NOTIMPL: HRESULT = @bitCast(@as(u32, 0x8000_4001));
const E_NOINTERFACE: HRESULT = @bitCast(@as(u32, 0x8000_4002));
const GAMEINPUT_E_DEVICE_NOT_FOUND: HRESULT = @bitCast(@as(u32, 0x838A_0002));
const GAMEINPUT_E_READING_NOT_FOUND: HRESULT = @bitCast(@as(u32, 0x838A_0003));

const GAMEINPUT_KIND_KEYBOARD: u32 = 0x10;
const GAMEINPUT_KIND_MOUSE: u32 = 0x20;
const DEVICE_STATUS_CONNECTED: u32 = 0x1;
const DEVICE_STATUS_INPUT_ENABLED: u32 = 0x2;
const DEVICE_STATUS_READY: u32 = DEVICE_STATUS_CONNECTED | DEVICE_STATUS_INPUT_ENABLED;

const MAX_DEVICES: usize = 8;
const KEY_MAX: usize = 256;

const Guid = extern struct { d1: u32, d2: u16, d3: u16, d4: [8]u8 };

fn iidIs(iid: ?*const anyopaque, d1: u32, d2: u16, d3: u16, d4: [8]u8) bool {
    const p = iid orelse return false;
    const g: *const Guid = @ptrCast(@alignCast(p));
    return g.d1 == d1 and g.d2 == d2 and g.d3 == d3 and std.mem.eql(u8, &g.d4, &d4);
}

fn iidIsUnknown(iid: ?*const anyopaque, own_d1: u32, own_d2: u16, own_d3: u16, own_d4: [8]u8) bool {
    return iidIs(iid, own_d1, own_d2, own_d3, own_d4) or
        iidIs(iid, 0, 0, 0, .{ 0xC0, 0, 0, 0, 0, 0, 0, 0x46 });
}

// GameInput.h IIDs.
const IID_IGAMEINPUT_D1: u32 = 0x11BE_2A7E;
const IID_IGAMEINPUT_D2: u16 = 0x4254;
const IID_IGAMEINPUT_D3: u16 = 0x445A;
const IID_IGAMEINPUT_D4 = [8]u8{ 0x9C, 0x09, 0xFF, 0xC4, 0x0F, 0x00, 0x69, 0x18 };
const IID_IREADING_D1: u32 = 0x2156_947A;
const IID_IREADING_D2: u16 = 0xE1FA;
const IID_IREADING_D3: u16 = 0x4DE0;
const IID_IREADING_D4 = [8]u8{ 0xA3, 0x0B, 0xD8, 0x12, 0x93, 0x1D, 0xBD, 0x8D };
const IID_IDEVICE_D1: u32 = 0x31DD_86FB;
const IID_IDEVICE_D2: u16 = 0x4C1B;
const IID_IDEVICE_D3: u16 = 0x408A;
const IID_IDEVICE_D4 = [8]u8{ 0x86, 0x8F, 0x43, 0x9B, 0x3C, 0xD4, 0x71, 0x25 };

// ---------------------------------------------------------------------------
// Public COM-ish interfaces
// ---------------------------------------------------------------------------

pub const IGameInputVtbl = extern struct {
    QueryInterface: *const fn (*IGameInput, ?*const anyopaque, *?*anyopaque) callconv(win) HRESULT,
    AddRef: *const fn (*IGameInput) callconv(win) u32,
    Release: *const fn (*IGameInput) callconv(win) u32,
    GetCurrentTimestamp: *const fn (*IGameInput) callconv(win) u64,
    GetCurrentReading: *const fn (*IGameInput, u32, ?*anyopaque, *?*anyopaque) callconv(win) HRESULT,
    GetNextReading: *const fn (*IGameInput, ?*anyopaque, u32, ?*anyopaque, *?*anyopaque) callconv(win) HRESULT,
    GetPreviousReading: *const fn (*IGameInput, ?*anyopaque, u32, ?*anyopaque, *?*anyopaque) callconv(win) HRESULT,
    GetTemporalReading: *const fn (*IGameInput, u64, ?*anyopaque, *?*anyopaque) callconv(win) HRESULT,
    RegisterReadingCallback: *const fn (*IGameInput, ?*anyopaque, u32, f32, ?*anyopaque, ?*anyopaque, ?*u64) callconv(win) HRESULT,
    RegisterDeviceCallback: *const fn (*IGameInput, ?*anyopaque, u32, u32, u32, ?*anyopaque, ?*anyopaque, ?*u64) callconv(win) HRESULT,
    RegisterGuideButtonCallback: *const fn (*IGameInput, ?*anyopaque, ?*anyopaque, ?*anyopaque, ?*u64) callconv(win) HRESULT,
    RegisterKeyboardLayoutCallback: *const fn (*IGameInput, ?*anyopaque, ?*anyopaque, ?*anyopaque, ?*u64) callconv(win) HRESULT,
    StopCallback: *const fn (*IGameInput, u64) callconv(win) void,
    UnregisterCallback: *const fn (*IGameInput, u64, u64) callconv(win) bool,
    CreateDispatcher: *const fn (*IGameInput, *?*anyopaque) callconv(win) HRESULT,
    CreateAggregateDevice: *const fn (*IGameInput, u32, *?*anyopaque) callconv(win) HRESULT,
    FindDeviceFromId: *const fn (*IGameInput, ?*const anyopaque, *?*anyopaque) callconv(win) HRESULT,
    FindDeviceFromObject: *const fn (*IGameInput, ?*anyopaque, *?*anyopaque) callconv(win) HRESULT,
    FindDeviceFromPlatformHandle: *const fn (*IGameInput, usize, *?*anyopaque) callconv(win) HRESULT,
    FindDeviceFromPlatformString: *const fn (*IGameInput, ?[*:0]const u16, *?*anyopaque) callconv(win) HRESULT,
    EnableOemDeviceSupport: *const fn (*IGameInput, u16, u16, u8, u8) callconv(win) HRESULT,
    SetFocusPolicy: *const fn (*IGameInput, u32) callconv(win) void,
};

pub const IGameInput = extern struct {
    lpVtbl: *const IGameInputVtbl,
};

pub const KeyState = extern struct {
    scan_code: u32,
    code_point: u32,
    virtual_key: u8,
    is_dead_key: bool,
};

pub const MouseState = extern struct {
    buttons: u32,
    position_x: i64,
    position_y: i64,
    wheel_x: i64,
    wheel_y: i64,
};

pub const BatteryState = extern struct {
    charge_rate: f32,
    max_charge_rate: f32,
    remaining_capacity: f32,
    full_charge_capacity: f32,
    status: i32, // GameInputBatteryNotPresent = 0
};

pub const IGameInputReadingVtbl = extern struct {
    QueryInterface: *const fn (*IGameInputReading, ?*const anyopaque, *?*anyopaque) callconv(win) HRESULT,
    AddRef: *const fn (*IGameInputReading) callconv(win) u32,
    Release: *const fn (*IGameInputReading) callconv(win) u32,
    GetInputKind: *const fn (*IGameInputReading) callconv(win) u32,
    GetSequenceNumber: *const fn (*IGameInputReading, u32) callconv(win) u64,
    GetTimestamp: *const fn (*IGameInputReading) callconv(win) u64,
    GetDevice: *const fn (*IGameInputReading, *?*anyopaque) callconv(win) void,
    GetRawReport: *const fn (*IGameInputReading, *?*anyopaque) callconv(win) bool,
    GetControllerAxisCount: *const fn (*IGameInputReading) callconv(win) u32,
    GetControllerAxisState: *const fn (*IGameInputReading, u32, ?[*]f32) callconv(win) u32,
    GetControllerButtonCount: *const fn (*IGameInputReading) callconv(win) u32,
    GetControllerButtonState: *const fn (*IGameInputReading, u32, ?[*]bool) callconv(win) u32,
    GetControllerSwitchCount: *const fn (*IGameInputReading) callconv(win) u32,
    GetControllerSwitchState: *const fn (*IGameInputReading, u32, ?*anyopaque) callconv(win) u32,
    GetKeyCount: *const fn (*IGameInputReading) callconv(win) u32,
    GetKeyState: *const fn (*IGameInputReading, u32, ?[*]KeyState) callconv(win) u32,
    GetMouseState: *const fn (*IGameInputReading, ?*MouseState) callconv(win) bool,
    GetTouchCount: *const fn (*IGameInputReading) callconv(win) u32,
    GetTouchState: *const fn (*IGameInputReading, u32, ?*anyopaque) callconv(win) u32,
    GetMotionState: *const fn (*IGameInputReading, ?*anyopaque) callconv(win) bool,
    GetArcadeStickState: *const fn (*IGameInputReading, ?*anyopaque) callconv(win) bool,
    GetFlightStickState: *const fn (*IGameInputReading, ?*anyopaque) callconv(win) bool,
    GetGamepadState: *const fn (*IGameInputReading, ?*anyopaque) callconv(win) bool,
    GetRacingWheelState: *const fn (*IGameInputReading, ?*anyopaque) callconv(win) bool,
    GetUiNavigationState: *const fn (*IGameInputReading, ?*anyopaque) callconv(win) bool,
};

pub const IGameInputReading = extern struct {
    lpVtbl: *const IGameInputReadingVtbl,
};

pub const DeviceInfo = extern struct {
    info_size: u32,
    vendor_id: u16,
    product_id: u16,
    revision: u16,
    interface_number: u8,
    collection_number: u8,
    usage: u16,
    hardware_version: [8]u8,
    firmware_version: [8]u8,
    device_id: [32]u8,
    device_root_id: [32]u8,
    device_family: u32,
    capabilities: u32,
    supported_input: u32,
    supported_rumble: u32,
    input_report_count: u32,
    output_report_count: u32,
    feature_report_count: u32,
    controller_axis_count: u32,
    controller_button_count: u32,
    controller_switch_count: u32,
    touch_point_count: u32,
    touch_sensor_count: u32,
    force_feedback_motor_count: u32,
    haptic_feedback_motor_count: u32,
    device_string_count: u32,
    device_descriptor_size: u32,
    optional_info: [28]usize,
};

pub const IGameInputDeviceVtbl = extern struct {
    QueryInterface: *const fn (*IGameInputDevice, ?*const anyopaque, *?*anyopaque) callconv(win) HRESULT,
    AddRef: *const fn (*IGameInputDevice) callconv(win) u32,
    Release: *const fn (*IGameInputDevice) callconv(win) u32,
    GetDeviceInfo: *const fn (*IGameInputDevice) callconv(win) *const DeviceInfo,
    GetDeviceStatus: *const fn (*IGameInputDevice) callconv(win) u32,
    GetBatteryState: *const fn (*IGameInputDevice, ?*BatteryState) callconv(win) void,
    CreateForceFeedbackEffect: *const fn (*IGameInputDevice, u32, ?*const anyopaque, *?*anyopaque) callconv(win) HRESULT,
    IsForceFeedbackMotorPoweredOn: *const fn (*IGameInputDevice, u32) callconv(win) bool,
    SetForceFeedbackMotorGain: *const fn (*IGameInputDevice, u32, f32) callconv(win) void,
    SetHapticMotorState: *const fn (*IGameInputDevice, u32, ?*const anyopaque) callconv(win) HRESULT,
    SetRumbleState: *const fn (*IGameInputDevice, ?*const anyopaque) callconv(win) void,
    SetInputSynchronizationState: *const fn (*IGameInputDevice, bool) callconv(win) void,
    SendInputSynchronizationHint: *const fn (*IGameInputDevice) callconv(win) void,
    PowerOff: *const fn (*IGameInputDevice) callconv(win) void,
    CreateRawDeviceReport: *const fn (*IGameInputDevice, u32, u32, *?*anyopaque) callconv(win) HRESULT,
    GetRawDeviceFeature: *const fn (*IGameInputDevice, u32, *?*anyopaque) callconv(win) HRESULT,
    SetRawDeviceFeature: *const fn (*IGameInputDevice, ?*anyopaque) callconv(win) HRESULT,
    SendRawDeviceOutput: *const fn (*IGameInputDevice, ?*anyopaque) callconv(win) HRESULT,
    SendRawDeviceOutputWithResponse: *const fn (*IGameInputDevice, ?*anyopaque, *?*anyopaque) callconv(win) HRESULT,
    ExecuteRawDeviceIoControl: *const fn (*IGameInputDevice, u32, usize, ?*const anyopaque, usize, ?*anyopaque, ?*usize) callconv(win) HRESULT,
    AcquireExclusiveRawDeviceAccess: *const fn (*IGameInputDevice, u64) callconv(win) bool,
    ReleaseExclusiveRawDeviceAccess: *const fn (*IGameInputDevice) callconv(win) void,
};

pub const IGameInputDevice = extern struct {
    lpVtbl: *const IGameInputDeviceVtbl,
};

const SpinLock = struct {
    v: std.atomic.Value(u32) = .init(0),
    fn lock(self: *SpinLock) void {
        while (self.v.cmpxchgWeak(0, 1, .acquire, .monotonic) != null) {
            while (self.v.load(.monotonic) != 0) std.atomic.spinLoopHint();
        }
    }
    fn unlock(self: *SpinLock) void {
        self.v.store(0, .release);
    }
};

const DeviceObject = struct {
    lpVtbl: *const IGameInputDeviceVtbl = undefined,
    refs: std.atomic.Value(u32) = .init(1),
    kind: u32 = 0,
    status: u32 = DEVICE_STATUS_READY,
    info: DeviceInfo = std.mem.zeroes(DeviceInfo),
};

const InputDevice = struct {
    used: bool = false,
    fd: c_int = -1,
    kind: u32 = 0,
    object: DeviceObject = undefined,
};

const KeyEntry = struct {
    scan_code: u32 = 0,
    code_point: u32 = 0,
    virtual_key: u8 = 0,
};

const ReadingObject = struct {
    lpVtbl: *const IGameInputReadingVtbl = undefined,
    refs: std.atomic.Value(u32) = .init(1),
    kind: u32 = 0,
    sequence: u64 = 0,
    timestamp: u64 = 0,
    device: ?*IGameInputDevice = null,
    keys: [32]KeyEntry = @splat(.{}),
    key_count: u32 = 0,
    mouse: MouseState = std.mem.zeroes(MouseState),
};

// ---------------------------------------------------------------------------
// evdev plumbing
// ---------------------------------------------------------------------------

const EV_KEY: u16 = 1;
const EV_REL: u16 = 2;
const REL_X: u16 = 0;
const REL_Y: u16 = 1;
const REL_HWHEEL: u16 = 6;
const REL_WHEEL: u16 = 8;
const BTN_LEFT: u16 = 0x110;
const BTN_RIGHT: u16 = 0x111;
const BTN_MIDDLE: u16 = 0x112;
const BTN_SIDE: u16 = 0x113;
const BTN_EXTRA: u16 = 0x114;
const KEY_ESC: u16 = 1;
const KEY_1: u16 = 2;
const KEY_0: u16 = 11;
const KEY_BACKSPACE: u16 = 14;
const KEY_TAB: u16 = 15;
const KEY_Q: u16 = 16;
const KEY_P: u16 = 25;
const KEY_ENTER: u16 = 28;
const KEY_LEFTCTRL: u16 = 29;
const KEY_A: u16 = 30;
const KEY_LEFTSHIFT: u16 = 42;
const KEY_Z: u16 = 44;
const KEY_M: u16 = 50;
const KEY_RIGHTSHIFT: u16 = 54;
const KEY_SPACE: u16 = 57;
const KEY_F1: u16 = 59;
const KEY_F10: u16 = 68;
const KEY_RIGHTCTRL: u16 = 97;
const KEY_RIGHTALT: u16 = 100;
const KEY_LEFT: u16 = 105;
const KEY_RIGHT: u16 = 106;
const KEY_UP: u16 = 103;
const KEY_DOWN: u16 = 108;
const KEY_F11: u16 = 87;
const KEY_F12: u16 = 88;

const InputEvent = extern struct {
    sec: i64,
    usec: i64,
    type: u16,
    code: u16,
    value: i32,
};

const PollFd = extern struct {
    fd: c_int,
    events: i16,
    revents: i16,
};

const sys = if (builtin.os.tag == .linux) struct {
    extern "c" fn open(path: [*:0]const u8, flags: c_int, ...) c_int;
    extern "c" fn read(fd: c_int, buf: ?*anyopaque, count: usize) isize;
    extern "c" fn poll(fds: [*]PollFd, nfds: c_ulong, timeout: c_int) c_int;
    extern "c" fn ioctl(fd: c_int, request: c_ulong, arg: ?*anyopaque) c_int;
} else struct {
    fn open(_: [*:0]const u8, _: c_int, ...) callconv(.c) c_int {
        return -1;
    }
    fn read(_: c_int, _: ?*anyopaque, _: usize) isize {
        return -1;
    }
    fn poll(_: [*]PollFd, _: c_ulong, _: c_int) c_int {
        return -1;
    }
    fn ioctl(_: c_int, _: c_ulong, _: ?*anyopaque) c_int {
        return -1;
    }
};

fn closeFd(fd: c_int) void {
    if (comptime builtin.os.tag == .linux) closeFd(fd);
}

fn ioc(dir: u32, typ: u8, nr: u8, size: usize) c_ulong {
    return (@as(c_ulong, dir) << 30) | (@as(c_ulong, @intCast(size & 0x3fff)) << 16) |
        (@as(c_ulong, typ) << 8) | @as(c_ulong, nr);
}
fn eviocgbit(ev: u16, len: usize) c_ulong {
    return ioc(2, 'E', 0x20 + @as(u8, @truncate(ev)), len);
}
fn eviocgname(len: usize) c_ulong {
    return ioc(2, 'E', 0x06, len);
}
fn bitSet(bits: []const u8, code: u16) bool {
    const index: usize = code / 8;
    if (index >= bits.len) return false;
    return (bits[index] & (@as(u8, 1) << @intCast(code % 8))) != 0;
}

var g_lock = SpinLock{};
var g_devices: [MAX_DEVICES]InputDevice = @splat(.{ .used = false });
var g_device_count: usize = 0;
var g_device_kinds: u32 = 0;
var g_keys: [KEY_MAX]bool = @splat(false);
var g_mouse_buttons: u32 = 0;
var g_mouse_x: i64 = 640;
var g_mouse_y: i64 = 360;
var g_wheel_x: i64 = 0;
var g_wheel_y: i64 = 0;
var g_sequence: u64 = 1;
var g_last_usec: u64 = 0;
var g_backend_state: enum { unstarted, unavailable, running } = .unstarted;
var g_backend_lock = SpinLock{};
var g_callback_token_next: u64 = 1;

fn nowUsec() u64 {
    if (comptime builtin.os.tag == .linux) {
        var ts: std.os.linux.timespec = undefined;
        _ = std.os.linux.clock_gettime(.MONOTONIC, &ts);
        return @as(u64, @intCast(ts.sec)) * 1_000_000 + @as(u64, @intCast(@divTrunc(ts.nsec, 1000)));
    }
    return 0; // input timestamps are only used on the Linux backend
}

fn makeDeviceInfo(kind: u32, name: []const u8) DeviceInfo {
    var info = std.mem.zeroes(DeviceInfo);
    info.info_size = @sizeOf(DeviceInfo);
    info.device_family = 3; // GameInputFamilyHid
    info.supported_input = kind;
    const hash = std.hash.Wyhash.hash(0x47616d65, name);
    for (&info.device_id, 0..) |*b, i| b.* = @truncate(hash >> @intCast((i % 8) * 8));
    info.device_root_id = info.device_id;
    return info;
}

fn classifyDevice(fd: c_int) u32 {
    var ev_bits: [8]u8 = @splat(0);
    if (sys.ioctl(fd, eviocgbit(0, ev_bits.len), &ev_bits) < 0) return 0;
    var key_bits: [96]u8 = @splat(0);
    const key_ok = sys.ioctl(fd, eviocgbit(EV_KEY, key_bits.len), &key_bits) >= 0;
    var rel_bits: [8]u8 = @splat(0);
    const rel_ok = sys.ioctl(fd, eviocgbit(EV_REL, rel_bits.len), &rel_bits) >= 0;
    if (!bitSet(&ev_bits, EV_KEY) or !key_ok) return 0;

    const has_keyboard = bitSet(&key_bits, KEY_A) and bitSet(&key_bits, KEY_Z) and
        bitSet(&key_bits, KEY_ENTER);
    const has_mouse = rel_ok and bitSet(&ev_bits, EV_REL) and bitSet(&rel_bits, REL_X) and
        bitSet(&key_bits, BTN_LEFT);
    var kind: u32 = 0;
    if (has_keyboard) kind |= GAMEINPUT_KIND_KEYBOARD;
    if (has_mouse) kind |= GAMEINPUT_KIND_MOUSE;
    return kind;
}

fn addDevice(fd: c_int, kind: u32) bool {
    var name: [64]u8 = @splat(0);
    _ = sys.ioctl(fd, eviocgname(name.len), &name);
    const name_slice = std.mem.sliceTo(&name, 0);
    const info = makeDeviceInfo(kind, name_slice);
    g_devices[g_device_count] = .{
        .used = true,
        .fd = fd,
        .kind = kind,
        .object = .{
            .lpVtbl = &g_device_vtbl,
            .refs = std.atomic.Value(u32).init(1),
            .kind = kind,
            .status = DEVICE_STATUS_READY,
            .info = info,
        },
    };
    std.log.info("[INPUT] evdev device '{s}' fd={d} kind=0x{x}", .{ name_slice, fd, kind });
    g_device_count += 1;
    g_device_kinds |= kind;
    return true;
}

fn readerMain() void {
    var fds: [MAX_DEVICES]PollFd = undefined;
    var count: usize = 0;
    for (g_devices[0..g_device_count]) |*device| {
        if (!device.used) continue;
        fds[count] = .{ .fd = device.fd, .events = 1, .revents = 0 }; // POLLIN
        count += 1;
    }
    if (count == 0) return;

    while (true) {
        const ready = sys.poll(&fds, @intCast(count), 100);
        if (ready <= 0) continue;
        for (fds[0..count]) |*pfd| {
            if ((pfd.revents & 1) == 0) continue; // POLLIN
            var events: [24 * 16]u8 align(8) = undefined;
            while (true) {
                const nread = sys.read(pfd.fd, &events, events.len);
                if (nread < @sizeOf(InputEvent)) break;
                var off: usize = 0;
                const total: usize = @intCast(nread);
                while (off + @sizeOf(InputEvent) <= total) : (off += @sizeOf(InputEvent)) {
                    const event: *const InputEvent = @ptrCast(@alignCast(&events[off]));
                    applyEvent(event);
                }
                if (total < events.len) break;
            }
        }
    }
}

fn applyEvent(event: *const InputEvent) void {
    g_lock.lock();
    defer g_lock.unlock();
    g_sequence +%= 1;
    g_last_usec = @as(u64, @intCast(event.sec)) * 1_000_000 + @as(u64, @intCast(event.usec));
    switch (event.type) {
        EV_KEY => {
            if (event.code < KEY_MAX) g_keys[event.code] = event.value != 0;
            switch (event.code) {
                BTN_LEFT => setMouseButton(0x1, event.value != 0),
                BTN_RIGHT => setMouseButton(0x2, event.value != 0),
                BTN_MIDDLE => setMouseButton(0x4, event.value != 0),
                BTN_SIDE => setMouseButton(0x8, event.value != 0),
                BTN_EXTRA => setMouseButton(0x10, event.value != 0),
                else => {},
            }
        },
        EV_REL => switch (event.code) {
            REL_X => g_mouse_x += event.value,
            REL_Y => g_mouse_y += event.value,
            REL_WHEEL => g_wheel_y += event.value,
            REL_HWHEEL => g_wheel_x += event.value,
            else => {},
        },
        else => {},
    }
}

fn setMouseButton(mask: u32, pressed: bool) void {
    if (pressed) {
        g_mouse_buttons |= mask;
    } else {
        g_mouse_buttons &= ~mask;
    }
}

fn ensureBackend() void {
    g_backend_lock.lock();
    defer g_backend_lock.unlock();
    if (g_backend_state != .unstarted) return;
    g_backend_state = .unavailable; // set to running only after a device opens

    var index: usize = 0;
    while (index < 32 and g_device_count < MAX_DEVICES) : (index += 1) {
        var path_buf: [32]u8 = undefined;
        const path_text = std.fmt.bufPrint(&path_buf, "/dev/input/event{d}", .{index}) catch continue;
        path_buf[path_text.len] = 0;
        const path: [*:0]const u8 = @ptrCast(&path_buf);
        const fd = sys.open(path, 0); // O_RDONLY; blocking is fine, poll/read
        if (fd < 0) continue;
        const kind = classifyDevice(fd);
        if (kind == 0) {
            closeFd(fd);
            continue;
        }
        _ = addDevice(fd, kind);
    }
    if (g_device_count == 0) {
        std.log.info("[INPUT] no readable /dev/input keyboard/mouse devices; GameInput will report not-found", .{});
        g_backend_state = .unavailable;
        return;
    }
    g_backend_state = .running;
    const thread = std.Thread.spawn(.{}, readerMain, .{}) catch {
        std.log.err("[INPUT] failed to start evdev reader thread; disabling input", .{});
        for (g_devices[0..g_device_count]) |*device| {
            if (device.used) closeFd(device.fd);
            device.used = false;
        }
        g_device_count = 0;
        g_device_kinds = 0;
        g_backend_state = .unavailable;
        return;
    };
    thread.detach();
}

pub fn backendDeviceCount() usize {
    ensureBackend();
    return g_device_count;
}

pub fn backendDeviceKinds() u32 {
    ensureBackend();
    return g_device_kinds;
}

fn vkFor(code: u16) u8 {
    if (code >= KEY_F1 and code <= KEY_F10) return @intCast(0x70 + (code - KEY_F1));
    return switch (code) {
        KEY_Q => 'Q',
        17 => 'W',
        18 => 'E',
        19 => 'R',
        20 => 'T',
        21 => 'Y',
        22 => 'U',
        23 => 'I',
        24 => 'O',
        KEY_P => 'P',
        KEY_A => 'A',
        31 => 'S',
        32 => 'D',
        33 => 'F',
        34 => 'G',
        35 => 'H',
        36 => 'J',
        37 => 'K',
        38 => 'L',
        KEY_Z => 'Z',
        45 => 'X',
        46 => 'C',
        47 => 'V',
        48 => 'B',
        49 => 'N',
        KEY_M => 'M',
        KEY_1 => '1',
        3 => '2',
        4 => '3',
        5 => '4',
        6 => '5',
        7 => '6',
        8 => '7',
        9 => '8',
        10 => '9',
        KEY_0 => '0',
        KEY_ENTER => 0x0D,
        KEY_ESC => 0x1B,
        KEY_BACKSPACE => 0x08,
        KEY_TAB => 0x09,
        KEY_SPACE => 0x20,
        KEY_UP => 0x26,
        KEY_DOWN => 0x28,
        KEY_LEFT => 0x25,
        KEY_RIGHT => 0x27,
        KEY_LEFTSHIFT, KEY_RIGHTSHIFT => 0x10,
        KEY_LEFTCTRL, KEY_RIGHTCTRL => 0x11,
        56, KEY_RIGHTALT => 0x12,
        KEY_F11 => 0x7B,
        KEY_F12 => 0x7C,
        else => 0,
    };
}

fn snapshotReading(input_kind: u32) ?*ReadingObject {
    ensureBackend();
    g_lock.lock();
    defer g_lock.unlock();
    if (g_device_count == 0) return null;
    const requested = if (input_kind == 0) g_device_kinds else input_kind;
    const kind = requested & g_device_kinds;
    if (kind == 0) return null;

    const reading = std.heap.page_allocator.create(ReadingObject) catch return null;
    reading.* = .{
        .lpVtbl = &g_reading_vtbl,
        .refs = std.atomic.Value(u32).init(1),
        .kind = kind,
        .sequence = g_sequence,
        .timestamp = g_last_usec,
        .device = null,
        .mouse = .{
            .buttons = g_mouse_buttons,
            .position_x = g_mouse_x,
            .position_y = g_mouse_y,
            .wheel_x = g_wheel_x,
            .wheel_y = g_wheel_y,
        },
    };
    for (g_devices[0..g_device_count]) |*device| {
        if (device.used and (device.kind & kind) != 0) {
            _ = device.object.refs.fetchAdd(1, .monotonic);
            reading.device = @ptrCast(&device.object);
            break;
        }
    }
    var count: u32 = 0;
    var code: usize = 0;
    while (code < KEY_MAX and count < reading.keys.len) : (code += 1) {
        if (!g_keys[code]) continue;
        const vk = vkFor(@intCast(code));
        reading.keys[count] = .{
            .scan_code = @intCast(code),
            .code_point = if (vk >= 0x20 and vk <= 0x7E) vk else 0,
            .virtual_key = vk,
        };
        count += 1;
    }
    reading.key_count = count;
    return reading;
}

// ---------------------------------------------------------------------------
// Reading object
// ---------------------------------------------------------------------------

fn asReading(self: *IGameInputReading) *ReadingObject {
    return @ptrCast(@alignCast(self));
}

fn readingQueryInterface(self: *IGameInputReading, iid: ?*const anyopaque, ppv: *?*anyopaque) callconv(win) HRESULT {
    if (!iidIsUnknown(iid, IID_IREADING_D1, IID_IREADING_D2, IID_IREADING_D3, IID_IREADING_D4)) return E_NOINTERFACE;
    ppv.* = self;
    _ = readingAddRef(self);
    return S_OK;
}
fn readingAddRef(self: *IGameInputReading) callconv(win) u32 {
    return asReading(self).refs.fetchAdd(1, .monotonic) + 1;
}
fn readingRelease(self: *IGameInputReading) callconv(win) u32 {
    const r = asReading(self);
    const remaining = r.refs.fetchSub(1, .acq_rel) - 1;
    if (remaining == 0) {
        if (r.device) |d| _ = d.lpVtbl.Release(d);
        std.heap.page_allocator.destroy(r);
    }
    return remaining;
}
fn readingKind(self: *IGameInputReading) callconv(win) u32 {
    return asReading(self).kind;
}
fn readingSequence(self: *IGameInputReading, input_kind: u32) callconv(win) u64 {
    const r = asReading(self);
    return if ((input_kind & r.kind) != 0) r.sequence else 0;
}
fn readingTimestamp(self: *IGameInputReading) callconv(win) u64 {
    return asReading(self).timestamp;
}
fn readingGetDevice(self: *IGameInputReading, out: *?*anyopaque) callconv(win) void {
    const r = asReading(self);
    if (r.device) |d| {
        _ = d.lpVtbl.AddRef(d);
        out.* = d;
    } else {
        out.* = null;
    }
}
fn readingFalse(_: *IGameInputReading, _: ?*anyopaque) callconv(win) bool {
    return false;
}
fn readingRawReport(_: *IGameInputReading, _: *?*anyopaque) callconv(win) bool {
    return false;
}
fn readingZero(_: *IGameInputReading) callconv(win) u32 {
    return 0;
}
fn readingZeroState(_: *IGameInputReading, _: u32, _: ?*anyopaque) callconv(win) u32 {
    return 0;
}
fn readingZeroAxis(_: *IGameInputReading, _: u32, _: ?[*]f32) callconv(win) u32 {
    return 0;
}
fn readingZeroButtons(_: *IGameInputReading, _: u32, _: ?[*]bool) callconv(win) u32 {
    return 0;
}
fn readingKeyCount(self: *IGameInputReading) callconv(win) u32 {
    return asReading(self).key_count;
}
fn readingKeyState(self: *IGameInputReading, count: u32, out: ?[*]KeyState) callconv(win) u32 {
    const r = asReading(self);
    const n = @min(count, r.key_count);
    if (out) |dst| {
        var i: u32 = 0;
        while (i < n) : (i += 1) {
            dst[i] = .{
                .scan_code = r.keys[i].scan_code,
                .code_point = r.keys[i].code_point,
                .virtual_key = r.keys[i].virtual_key,
                .is_dead_key = false,
            };
        }
    }
    return n;
}
fn readingMouseState(self: *IGameInputReading, out: ?*MouseState) callconv(win) bool {
    const r = asReading(self);
    if ((r.kind & GAMEINPUT_KIND_MOUSE) == 0) return false;
    if (out) |dst| dst.* = r.mouse;
    return true;
}

const g_reading_vtbl = IGameInputReadingVtbl{
    .QueryInterface = &readingQueryInterface,
    .AddRef = &readingAddRef,
    .Release = &readingRelease,
    .GetInputKind = &readingKind,
    .GetSequenceNumber = &readingSequence,
    .GetTimestamp = &readingTimestamp,
    .GetDevice = &readingGetDevice,
    .GetRawReport = &readingRawReport,
    .GetControllerAxisCount = &readingZero,
    .GetControllerAxisState = &readingZeroAxis,
    .GetControllerButtonCount = &readingZero,
    .GetControllerButtonState = &readingZeroButtons,
    .GetControllerSwitchCount = &readingZero,
    .GetControllerSwitchState = &readingZeroState,
    .GetKeyCount = &readingKeyCount,
    .GetKeyState = &readingKeyState,
    .GetMouseState = &readingMouseState,
    .GetTouchCount = &readingZero,
    .GetTouchState = &readingZeroState,
    .GetMotionState = &readingFalse,
    .GetArcadeStickState = &readingFalse,
    .GetFlightStickState = &readingFalse,
    .GetGamepadState = &readingFalse,
    .GetRacingWheelState = &readingFalse,
    .GetUiNavigationState = &readingFalse,
};

// ---------------------------------------------------------------------------
// Device object
// ---------------------------------------------------------------------------

fn asDevice(self: *IGameInputDevice) *DeviceObject {
    return @ptrCast(@alignCast(self));
}
fn deviceQueryInterface(self: *IGameInputDevice, iid: ?*const anyopaque, ppv: *?*anyopaque) callconv(win) HRESULT {
    if (!iidIsUnknown(iid, IID_IDEVICE_D1, IID_IDEVICE_D2, IID_IDEVICE_D3, IID_IDEVICE_D4)) return E_NOINTERFACE;
    ppv.* = self;
    _ = deviceAddRef(self);
    return S_OK;
}
fn deviceAddRef(self: *IGameInputDevice) callconv(win) u32 {
    return asDevice(self).refs.fetchAdd(1, .monotonic) + 1;
}
fn deviceRelease(self: *IGameInputDevice) callconv(win) u32 {
    const d = asDevice(self);
    const remaining = d.refs.fetchSub(1, .acq_rel) - 1;
    if (remaining == 0) {
        // Devices are owned by the backend for the process lifetime.
        d.refs.store(1, .release);
    }
    return remaining;
}
fn deviceInfo(self: *IGameInputDevice) callconv(win) *const DeviceInfo {
    return &asDevice(self).info;
}
fn deviceStatus(self: *IGameInputDevice) callconv(win) u32 {
    return asDevice(self).status;
}
fn deviceBattery(_: *IGameInputDevice, out: ?*BatteryState) callconv(win) void {
    if (out) |b| b.* = .{ .charge_rate = 0, .max_charge_rate = 0, .remaining_capacity = 0, .full_charge_capacity = 0, .status = 0 };
}
fn deviceVoid(_: *IGameInputDevice) callconv(win) void {}
fn deviceFalseMotor(_: *IGameInputDevice, _: u32) callconv(win) bool {
    return false;
}
fn deviceVoidGain(_: *IGameInputDevice, _: u32, _: f32) callconv(win) void {}
fn deviceVoidRumble(_: *IGameInputDevice, _: ?*const anyopaque) callconv(win) void {}
fn deviceVoidSync(_: *IGameInputDevice, _: bool) callconv(win) void {}
fn deviceFalseAcquire(_: *IGameInputDevice, _: u64) callconv(win) bool {
    return false;
}
fn deviceCreateEffect(_: *IGameInputDevice, _: u32, _: ?*const anyopaque, _: *?*anyopaque) callconv(win) HRESULT {
    return E_NOTIMPL;
}
fn deviceCreateRawReport(_: *IGameInputDevice, _: u32, _: u32, _: *?*anyopaque) callconv(win) HRESULT {
    return E_NOTIMPL;
}
fn deviceGetRawFeature(_: *IGameInputDevice, _: u32, _: *?*anyopaque) callconv(win) HRESULT {
    return E_NOTIMPL;
}
fn deviceSetRawFeature(_: *IGameInputDevice, _: ?*anyopaque) callconv(win) HRESULT {
    return E_NOTIMPL;
}
fn deviceSendRaw(_: *IGameInputDevice, _: ?*anyopaque) callconv(win) HRESULT {
    return E_NOTIMPL;
}
fn deviceSendRawResponse(_: *IGameInputDevice, _: ?*anyopaque, _: *?*anyopaque) callconv(win) HRESULT {
    return E_NOTIMPL;
}
fn deviceIoControl(_: *IGameInputDevice, _: u32, _: usize, _: ?*const anyopaque, _: usize, _: ?*anyopaque, _: ?*usize) callconv(win) HRESULT {
    return E_NOTIMPL;
}
fn deviceHapticNotImpl(_: *IGameInputDevice, _: u32, _: ?*const anyopaque) callconv(win) HRESULT {
    return E_NOTIMPL;
}

const g_device_vtbl = IGameInputDeviceVtbl{
    .QueryInterface = &deviceQueryInterface,
    .AddRef = &deviceAddRef,
    .Release = &deviceRelease,
    .GetDeviceInfo = &deviceInfo,
    .GetDeviceStatus = &deviceStatus,
    .GetBatteryState = &deviceBattery,
    .CreateForceFeedbackEffect = &deviceCreateEffect,
    .IsForceFeedbackMotorPoweredOn = &deviceFalseMotor,
    .SetForceFeedbackMotorGain = &deviceVoidGain,
    .SetHapticMotorState = &deviceHapticNotImpl,
    .SetRumbleState = &deviceVoidRumble,
    .SetInputSynchronizationState = &deviceVoidSync,
    .SendInputSynchronizationHint = &deviceVoid,
    .PowerOff = &deviceVoid,
    .CreateRawDeviceReport = &deviceCreateRawReport,
    .GetRawDeviceFeature = &deviceGetRawFeature,
    .SetRawDeviceFeature = &deviceSetRawFeature,
    .SendRawDeviceOutput = &deviceSendRaw,
    .SendRawDeviceOutputWithResponse = &deviceSendRawResponse,
    .ExecuteRawDeviceIoControl = &deviceIoControl,
    .AcquireExclusiveRawDeviceAccess = &deviceFalseAcquire,
    .ReleaseExclusiveRawDeviceAccess = &deviceVoid,
};

// ---------------------------------------------------------------------------
// IGameInput
// ---------------------------------------------------------------------------

var g_game_input = IGameInput{ .lpVtbl = &g_game_input_vtbl };
var g_focus_policy: u32 = 0;

fn giQueryInterface(self: *IGameInput, iid: ?*const anyopaque, ppv: *?*anyopaque) callconv(win) HRESULT {
    if (!iidIsUnknown(iid, IID_IGAMEINPUT_D1, IID_IGAMEINPUT_D2, IID_IGAMEINPUT_D3, IID_IGAMEINPUT_D4)) return E_NOINTERFACE;
    ppv.* = self;
    _ = giAddRef(self);
    return S_OK;
}
fn giAddRef(_: *IGameInput) callconv(win) u32 {
    return 2;
}
fn giRelease(_: *IGameInput) callconv(win) u32 {
    return 1;
}
fn giTimestamp(_: *IGameInput) callconv(win) u64 {
    return nowUsec();
}
fn giCurrentReading(_: *IGameInput, input_kind: u32, device: ?*anyopaque, out: *?*anyopaque) callconv(win) HRESULT {
    _ = device;
    out.* = null;
    const reading = snapshotReading(input_kind) orelse return GAMEINPUT_E_READING_NOT_FOUND;
    out.* = reading;
    return S_OK;
}
fn giNoReading(_: *IGameInput, _: ?*anyopaque, _: u32, _: ?*anyopaque, out: *?*anyopaque) callconv(win) HRESULT {
    out.* = null;
    return GAMEINPUT_E_READING_NOT_FOUND;
}
fn giTemporalReading(_: *IGameInput, _: u64, _: ?*anyopaque, out: *?*anyopaque) callconv(win) HRESULT {
    out.* = null;
    return GAMEINPUT_E_READING_NOT_FOUND;
}
fn giRegisterReadingCallback(_: *IGameInput, _: ?*anyopaque, _: u32, _: f32, _: ?*anyopaque, _: ?*anyopaque, token: ?*u64) callconv(win) HRESULT {
    if (token) |t| t.* = 0;
    // Reading callbacks are not implemented; poll GetCurrentReading instead.
    return E_NOTIMPL;
}
const DeviceCallback = *const fn (u64, ?*anyopaque, *IGameInputDevice, u64, u32, u32) callconv(win) void;
fn giRegisterDeviceCallback(
    _: *IGameInput,
    _: ?*anyopaque,
    input_kind: u32,
    status_filter: u32,
    enumeration_kind: u32,
    context: ?*anyopaque,
    callback: ?*anyopaque,
    token_out: ?*u64,
) callconv(win) HRESULT {
    _ = status_filter;
    _ = enumeration_kind;
    if (token_out) |t| t.* = 0;
    const cb = callback orelse return E_INVALIDARG;
    ensureBackend();
    if (g_device_count == 0) return GAMEINPUT_E_DEVICE_NOT_FOUND;

    const token = g_callback_token_next;
    g_callback_token_next += 1;
    if (token_out) |t| t.* = token;
    const cb_fn: DeviceCallback = @ptrCast(cb);
    const timestamp = nowUsec();
    // Invoke on the guest thread for every matching existing device.  No
    // callback is stored for later hotplug events, so Unregister is a no-op
    // that succeeds only for issued tokens.
    var matched: usize = 0;
    for (g_devices[0..g_device_count]) |*device| {
        if (!device.used) continue;
        if (input_kind != 0 and (device.kind & input_kind) == 0) continue;
        matched += 1;
        cb_fn(token, context, @ptrCast(&device.object), timestamp, device.object.status, 0);
    }
    if (matched == 0) {
        if (token_out) |t| t.* = 0;
        return GAMEINPUT_E_DEVICE_NOT_FOUND;
    }
    return S_OK;
}
fn giRegisterGuide(_: *IGameInput, _: ?*anyopaque, _: ?*anyopaque, _: ?*anyopaque, token: ?*u64) callconv(win) HRESULT {
    if (token) |t| t.* = 0;
    return E_NOTIMPL;
}
fn giRegisterKeyboardLayout(_: *IGameInput, _: ?*anyopaque, _: ?*anyopaque, _: ?*anyopaque, token: ?*u64) callconv(win) HRESULT {
    if (token) |t| t.* = 0;
    return E_NOTIMPL;
}
fn giStopCallback(_: *IGameInput, _: u64) callconv(win) void {}
fn giUnregisterCallback(_: *IGameInput, token: u64, _: u64) callconv(win) bool {
    return token != 0 and token < g_callback_token_next;
}
fn giCreateDispatcher(_: *IGameInput, out: *?*anyopaque) callconv(win) HRESULT {
    out.* = null;
    return E_NOTIMPL; // polling GetCurrentReading is supported instead
}
fn giCreateAggregateDevice(_: *IGameInput, _: u32, out: *?*anyopaque) callconv(win) HRESULT {
    out.* = null;
    return E_NOTIMPL;
}
fn giFindDevice(_: *IGameInput, _: ?*const anyopaque, out: *?*anyopaque) callconv(win) HRESULT {
    out.* = null;
    return GAMEINPUT_E_DEVICE_NOT_FOUND;
}
fn giFindDeviceFromObject(_: *IGameInput, _: ?*anyopaque, out: *?*anyopaque) callconv(win) HRESULT {
    out.* = null;
    return GAMEINPUT_E_DEVICE_NOT_FOUND;
}
fn giFindDeviceFromHandle(_: *IGameInput, handle: usize, out: *?*anyopaque) callconv(win) HRESULT {
    out.* = null;
    ensureBackend();
    for (g_devices[0..g_device_count]) |*device| {
        if (device.used and @as(usize, @intCast(device.fd)) == handle) {
            _ = device.object.refs.fetchAdd(1, .monotonic);
            out.* = @ptrCast(&device.object);
            return S_OK;
        }
    }
    return GAMEINPUT_E_DEVICE_NOT_FOUND;
}
fn giFindDeviceFromString(_: *IGameInput, _: ?[*:0]const u16, out: *?*anyopaque) callconv(win) HRESULT {
    out.* = null;
    return GAMEINPUT_E_DEVICE_NOT_FOUND;
}
fn giEnableOem(_: *IGameInput, _: u16, _: u16, _: u8, _: u8) callconv(win) HRESULT {
    return E_NOTIMPL;
}
fn giSetFocusPolicy(_: *IGameInput, policy: u32) callconv(win) void {
    g_focus_policy = policy;
}

const g_game_input_vtbl = IGameInputVtbl{
    .QueryInterface = &giQueryInterface,
    .AddRef = &giAddRef,
    .Release = &giRelease,
    .GetCurrentTimestamp = &giTimestamp,
    .GetCurrentReading = &giCurrentReading,
    .GetNextReading = &giNoReading,
    .GetPreviousReading = &giNoReading,
    .GetTemporalReading = &giTemporalReading,
    .RegisterReadingCallback = &giRegisterReadingCallback,
    .RegisterDeviceCallback = &giRegisterDeviceCallback,
    .RegisterGuideButtonCallback = &giRegisterGuide,
    .RegisterKeyboardLayoutCallback = &giRegisterKeyboardLayout,
    .StopCallback = &giStopCallback,
    .UnregisterCallback = &giUnregisterCallback,
    .CreateDispatcher = &giCreateDispatcher,
    .CreateAggregateDevice = &giCreateAggregateDevice,
    .FindDeviceFromId = &giFindDevice,
    .FindDeviceFromObject = &giFindDeviceFromObject,
    .FindDeviceFromPlatformHandle = &giFindDeviceFromHandle,
    .FindDeviceFromPlatformString = &giFindDeviceFromString,
    .EnableOemDeviceSupport = &giEnableOem,
    .SetFocusPolicy = &giSetFocusPolicy,
};

pub fn virtualKeyForTest(code: u16) u8 {
    return vkFor(code);
}

pub fn shim_GameInputCreate(out_game_input: ?*?*IGameInput) callconv(win) HRESULT {
    ensureBackend();
    std.log.info("[INPUT] GameInputCreate() -> S_OK (devices={d}, kinds=0x{x})", .{
        g_device_count, g_device_kinds,
    });
    if (out_game_input) |out| out.* = &g_game_input;
    return S_OK;
}

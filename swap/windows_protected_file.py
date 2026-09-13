"""Handle-bound Windows reader for protected operator files."""
import ctypes
from ctypes import wintypes as w
import os


def read_protected_file(path, maximum, description, *, private=False):
    if os.name != "nt":
        raise OSError("Windows protected-file reader requires Windows")
    if type(maximum) is not int or not 0 < maximum <= 64 * 1024 * 1024:
        raise ValueError("protected-file read limit is invalid")
    path = os.fspath(path).replace("/", "\\")
    drive, tail = os.path.splitdrive(path)
    if (len(drive) != 2 or drive[1] != ":" or not drive[0].isalpha() or
            not tail.startswith("\\") or "\x00" in path or
            any(not p or p.endswith((".", " ")) or ":" in p
                for p in tail[1:].split("\\"))):
        raise ValueError("%s requires an unambiguous local drive path" % description)
    path = os.path.abspath(path)
    kernel = ctypes.WinDLL("kernel32", use_last_error=True)
    advapi = ctypes.WinDLL("advapi32", use_last_error=True)
    ptr = ctypes.c_void_p

    class FileInfo(ctypes.Structure):
        _fields_ = [("attributes", w.DWORD), ("created", w.FILETIME),
                    ("accessed", w.FILETIME), ("written", w.FILETIME),
                    ("volume", w.DWORD), ("size_high", w.DWORD),
                    ("size_low", w.DWORD), ("links", w.DWORD),
                    ("index_high", w.DWORD), ("index_low", w.DWORD)]

    class Acl(ctypes.Structure):
        _fields_ = [("revision", w.BYTE), ("reserved", w.BYTE),
                    ("size", w.WORD), ("count", w.WORD), ("reserved2", w.WORD)]

    class Ace(ctypes.Structure):
        _fields_ = [("kind", w.BYTE), ("flags", w.BYTE), ("size", w.WORD),
                    ("mask", w.DWORD)]

    def api(library, name, result, *args):
        function = getattr(library, name)
        function.restype, function.argtypes = result, args
        return function

    close = api(kernel, "CloseHandle", w.BOOL, w.HANDLE)
    local_free = api(kernel, "LocalFree", ptr, ptr)
    create = api(kernel, "CreateFileW", w.HANDLE, w.LPCWSTR, w.DWORD,
                 w.DWORD, ptr, w.DWORD, w.DWORD, w.HANDLE)
    get_info = api(kernel, "GetFileInformationByHandle", w.BOOL,
                   w.HANDLE, ctypes.POINTER(FileInfo))
    file_type = api(kernel, "GetFileType", w.DWORD, w.HANDLE)
    final_path = api(kernel, "GetFinalPathNameByHandleW", w.DWORD,
                     w.HANDLE, w.LPWSTR, w.DWORD, w.DWORD)
    read_file = api(kernel, "ReadFile", w.BOOL, w.HANDLE, ptr, w.DWORD,
                    ctypes.POINTER(w.DWORD), ptr)
    process = api(kernel, "GetCurrentProcess", w.HANDLE)
    open_token = api(advapi, "OpenProcessToken", w.BOOL, w.HANDLE,
                     w.DWORD, ctypes.POINTER(w.HANDLE))
    token_info = api(advapi, "GetTokenInformation", w.BOOL, w.HANDLE,
                     ctypes.c_int, ptr, w.DWORD, ctypes.POINTER(w.DWORD))
    security_info = api(advapi, "GetSecurityInfo", w.DWORD, w.HANDLE,
                        ctypes.c_int, w.DWORD, ctypes.POINTER(ptr), ptr,
                        ctypes.POINTER(ptr), ptr, ctypes.POINTER(ptr))
    sid_length = api(advapi, "GetLengthSid", w.DWORD, ptr)
    valid_sid = api(advapi, "IsValidSid", w.BOOL, ptr)
    sid_text = api(advapi, "ConvertSidToStringSidW", w.BOOL, ptr,
                   ctypes.POINTER(ptr))
    valid_acl = api(advapi, "IsValidAcl", w.BOOL, ptr)
    get_ace = api(advapi, "GetAce", w.BOOL, ptr, w.DWORD, ctypes.POINTER(ptr))
    sd_control = api(advapi, "GetSecurityDescriptorControl", w.BOOL, ptr,
                     ctypes.POINTER(w.WORD), ctypes.POINTER(w.DWORD))

    def fail(message):
        raise ValueError("%s: %s" % (description, message))

    def sid_string(sid):
        if not sid or not valid_sid(sid):
            fail("invalid security principal")
        text = ptr()
        if not sid_text(sid, ctypes.byref(text)):
            fail("cannot inspect security principal")
        try:
            return ctypes.wstring_at(text)
        finally:
            local_free(text)

    token = w.HANDLE()
    if not open_token(process(), 8, ctypes.byref(token)):
        fail("cannot inspect current Windows identity")
    try:
        size = w.DWORD()
        token_info(token, 1, None, 0, ctypes.byref(size))
        if not ctypes.sizeof(ptr) <= size.value <= 65536:
            fail("invalid Windows identity size")
        user = ctypes.create_string_buffer(size.value)
        if not token_info(token, 1, user, size, ctypes.byref(size)):
            fail("cannot read current Windows identity")
        current_sid = sid_string(ptr.from_buffer(user).value)
    finally:
        close(token)

    # Do not share writes or deletion between handle validation and the read.
    handle = create(path, 0x80000000 | 0x00020000, 1, None, 3, 0x00200000, None)
    if handle == ctypes.c_void_p(-1).value:
        raise OSError(ctypes.get_last_error(), "%s cannot be opened safely" % description)
    descriptor = ptr()
    try:
        before = FileInfo()
        if (file_type(handle) != 1 or not get_info(handle, ctypes.byref(before)) or
                before.attributes & (0x10 | 0x400) or before.links != 1):
            fail("requires a regular, non-reparse, single-link file")
        length = (before.size_high << 32) | before.size_low
        if length > maximum:
            fail("file exceeds its read limit")
        name = ctypes.create_unicode_buffer(32768)
        count = final_path(handle, name, len(name), 0)
        if (not count or count >= len(name) or
                os.path.normcase(name.value) != os.path.normcase("\\\\?\\" + path)):
            fail("file resolved through an unexpected path")
        owner, dacl = ptr(), ptr()
        if (security_info(handle, 1, 1 | 4, ctypes.byref(owner), None,
                          ctypes.byref(dacl), None, ctypes.byref(descriptor)) or
                not descriptor or not dacl or not valid_acl(dacl)):
            fail("file requires a valid explicit access-control list")
        trusted = {current_sid, "S-1-5-18", "S-1-5-32-544"}
        if sid_string(owner) not in ({current_sid} if private else trusted):
            fail("file has an untrusted owner")
        control, revision = w.WORD(), w.DWORD()
        if not sd_control(descriptor, ctypes.byref(control), ctypes.byref(revision)):
            fail("cannot inspect access-control inheritance")
        if private and not control.value & 0x1000:
            fail("private file requires a protected owner-only DACL")
        acl = ctypes.cast(dacl, ctypes.POINTER(Acl)).contents
        owner_access = False
        for index in range(acl.count):
            address = ptr()
            if not get_ace(dacl, index, ctypes.byref(address)) or not address:
                fail("invalid access-control entry")
            entry = ctypes.cast(address, ctypes.POINTER(Ace)).contents
            if entry.kind == 1 or entry.flags & 8:
                continue
            if entry.kind != 0 or entry.size < 16:
                fail("unsupported access-control entry")
            sid = address.value + ctypes.sizeof(Ace)
            if not valid_sid(sid) or sid_length(sid) > entry.size - ctypes.sizeof(Ace):
                fail("invalid access-control principal")
            principal = sid_string(sid)
            owner_access |= principal == current_sid and bool(entry.mask & (1 | 0x80000000 | 0x10000000))
            if private and principal != current_sid and entry.mask:
                fail("private file grants access beyond its owner")
            write_mask = 2 | 4 | 16 | 256 | 0x10000 | 0x40000 | 0x80000 | 0x40000000 | 0x10000000 | 0x02000000
            if principal not in trusted and entry.mask & write_mask:
                fail("file grants write or policy authority to an untrusted principal")
        if private and not owner_access:
            fail("private file does not grant its owner read access")
        chunks, remaining = [], length
        while remaining:
            buffer = ctypes.create_string_buffer(min(remaining, 1024 * 1024))
            actual = w.DWORD()
            if not read_file(handle, buffer, len(buffer), ctypes.byref(actual), None) or not actual.value:
                fail("file changed or could not be read completely")
            chunks.append(buffer.raw[:actual.value])
            remaining -= actual.value
        after = FileInfo()
        if (not get_info(handle, ctypes.byref(after)) or
                any(getattr(before, f) != getattr(after, f) for f in
                    ("attributes", "volume", "size_high", "size_low", "links",
                     "index_high", "index_low")) or
                bytes(before.written) != bytes(after.written)):
            fail("file identity or metadata changed during read")
        return b"".join(chunks)
    finally:
        if descriptor:
            local_free(descriptor)
        close(handle)

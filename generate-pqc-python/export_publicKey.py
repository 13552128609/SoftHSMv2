import ctypes
import binascii

# 1. Load SoftHSM PKCS#11 library
lib = ctypes.CDLL('/usr/local/lib/softhsm/libsofthsm2.so')

# 2. PKCS#11 core types and constants
CK_SESSION_HANDLE = ctypes.c_ulong
CK_OBJECT_HANDLE = ctypes.c_ulong

CKA_CLASS = 0x00000000
CKA_TOKEN = 0x00000001
CKA_LABEL = 0x00000003
CKA_ID = 0x00000102
CKA_VALUE = 0x00000011

CKO_PUBLIC_KEY = 0x00000002

CKF_RW_SESSION = 0x00000002
CKF_SERIAL_SESSION = 0x00000004
CKU_USER = 1


class CK_ATTRIBUTE(ctypes.Structure):
    _fields_ = [
        ("type", ctypes.c_ulong),
        ("pValue", ctypes.c_void_p),
        ("ulValueLen", ctypes.c_ulong),
    ]


# 3. Initialize library
rv = lib.C_Initialize(None)
if rv not in (0,):
    raise SystemExit(f"C_Initialize failed: 0x{rv:x}")

try:
    # 4. Open session (Slot ID must match generate_pqc.py)
    session = CK_SESSION_HANDLE()
    flags = CKF_RW_SESSION | CKF_SERIAL_SESSION
    slot_id = ctypes.c_ulong(383231617)
    rv = lib.C_OpenSession(slot_id, flags, None, None, ctypes.byref(session))
    if rv != 0:
        raise SystemExit(f"C_OpenSession failed: 0x{rv:x}")

    # 5. Login
    pin = b"123456"
    rv = lib.C_Login(session, CKU_USER, pin, len(pin))
    if rv != 0:
        raise SystemExit(f"C_Login failed: 0x{rv:x}")

    print("[export_publicKey] Logged in, searching for ML-DSA public key ...")

    # 6. Find public key (same label/ID as generate_pqc.py)
    label = b"Jacob_PQ_Sign_Key"
    key_id = b"\x00\x01"

    obj_class = ctypes.c_ulong(CKO_PUBLIC_KEY)
    label_buf = ctypes.create_string_buffer(label)
    id_buf = ctypes.create_string_buffer(key_id)

    attr_class = CK_ATTRIBUTE(CKA_CLASS, ctypes.cast(ctypes.byref(obj_class), ctypes.c_void_p), ctypes.sizeof(obj_class))
    attr_label = CK_ATTRIBUTE(CKA_LABEL, ctypes.cast(label_buf, ctypes.c_void_p), len(label))
    attr_id = CK_ATTRIBUTE(CKA_ID, ctypes.cast(id_buf, ctypes.c_void_p), len(key_id))

    template = (CK_ATTRIBUTE * 3)(attr_class, attr_label, attr_id)

    rv = lib.C_FindObjectsInit(session, ctypes.byref(template), 3)
    if rv != 0:
        raise SystemExit(f"C_FindObjectsInit failed: 0x{rv:x}")

    try:
        obj = CK_OBJECT_HANDLE()
        count = ctypes.c_ulong()
        rv = lib.C_FindObjects(session, ctypes.byref(obj), 1, ctypes.byref(count))
        if rv != 0:
            raise SystemExit(f"C_FindObjects failed: 0x{rv:x}")
        if count.value == 0:
            raise SystemExit("No matching public key found (label/id/class).")
        pub_handle = obj
    finally:
        lib.C_FindObjectsFinal(session)

    print(f"[export_publicKey] Found public key handle: {pub_handle.value}")

    # 7. Query CKA_VALUE length
    value_len = ctypes.c_ulong(0)
    attr_template = CK_ATTRIBUTE(
        CKA_VALUE,
        None,
        0,
    )

    rv = lib.C_GetAttributeValue(session, pub_handle, ctypes.byref(attr_template), 1)
    if rv != 0:
        raise SystemExit(f"C_GetAttributeValue (length) failed: 0x{rv:x}")

    if attr_template.ulValueLen == 0xFFFFFFFFFFFFFFFF or attr_template.ulValueLen == 0:
        raise SystemExit("Invalid CKA_VALUE length returned")

    value_len.value = attr_template.ulValueLen

    # 8. Allocate buffer and fetch CKA_VALUE
    buf = (ctypes.c_ubyte * value_len.value)()
    attr_template.pValue = ctypes.cast(buf, ctypes.c_void_p)
    attr_template.ulValueLen = value_len.value

    rv = lib.C_GetAttributeValue(session, pub_handle, ctypes.byref(attr_template), 1)
    if rv != 0:
        raise SystemExit(f"C_GetAttributeValue (value) failed: 0x{rv:x}")

    pub_bytes = bytes(buf[: attr_template.ulValueLen])

    # 9. Write as hex string ("字节码") to file
    hex_str = binascii.hexlify(pub_bytes).decode("ascii")
    with open("public_key.hex", "w", encoding="ascii") as f:
        f.write(hex_str)

    print(f"[export_publicKey] Exported public key, length = {len(pub_bytes)} bytes")
    print("[export_publicKey] Hex-encoded public key written to public_key.hex")

finally:
    lib.C_Finalize(None)

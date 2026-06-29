import ctypes
import os
import binascii

# 1. Load SoftHSM PKCS#11 library
lib = ctypes.CDLL('/usr/local/lib/softhsm/libsofthsm2.so')

# 2. PKCS#11 core types and constants
CK_SESSION_HANDLE = ctypes.c_ulong
CK_OBJECT_HANDLE = ctypes.c_ulong

CKM_ML_DSA_44 = 0x80001001  # CKM_VENDOR_DEFINED + 0x1001 (must match pkcs11.h)

CKA_CLASS = 0x00000000
CKA_TOKEN = 0x00000001
CKA_LABEL = 0x00000003
CKA_ID = 0x00000102
CKA_PARAMETER_SET = 0x0000061D

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


class CK_MECHANISM(ctypes.Structure):
    _fields_ = [
        ("mechanism", ctypes.c_ulong),
        ("pParameter", ctypes.c_void_p),
        ("ulParameterLen", ctypes.c_ulong),
    ]


def read_hex_file(path: str) -> bytes:
    """Read ASCII hex file and return raw bytes."""
    with open(path, "r", encoding="ascii") as f:
        hex_str = f.read().strip()
    if not hex_str:
        return b""
    return binascii.unhexlify(hex_str)


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

    # 5. Login (same PIN as in generate_pqc.py)
    pin = b"123456"
    rv = lib.C_Login(session, CKU_USER, pin, len(pin))
    if rv != 0:
        raise SystemExit(f"C_Login failed: 0x{rv:x}")

    print("[verify_pqc] Logged in, searching for ML-DSA public key ...")

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

    print(f"[verify_pqc] Found public key handle: {pub_handle.value}")

    # 7. Read message and signature from files
    msg_path = "message.bin"
    sig_path = "signature.bin"

    if not os.path.exists(msg_path):
        raise SystemExit(f"Message file not found: {msg_path}")
    if not os.path.exists(sig_path):
        raise SystemExit(f"Signature file not found: {sig_path}")

    message = read_hex_file(msg_path)
    signature = read_hex_file(sig_path)

    print(f"[verify_pqc] Read message ({len(message)} bytes) and signature ({len(signature)} bytes)")

    # 8. Setup verify mechanism (ML-DSA-44)
    mech = CK_MECHANISM(CKM_ML_DSA_44, None, 0)

    rv = lib.C_VerifyInit(session, ctypes.byref(mech), pub_handle)
    if rv != 0:
        raise SystemExit(f"C_VerifyInit failed: 0x{rv:x}")

    # 9. Perform verify
    rv = lib.C_Verify(session,
                      message, len(message),
                      signature, len(signature))

    if rv == 0:
        print("[verify_pqc] Signature verification SUCCESS")
    elif rv == 0x000000CE:  # CKR_SIGNATURE_INVALID (if using PKCS#11 v2 code values)
        print("[verify_pqc] Signature verification FAILED (CKR_SIGNATURE_INVALID)")
    else:
        print(f"[verify_pqc] C_Verify returned error: 0x{rv:x}")

finally:
    lib.C_Finalize(None)

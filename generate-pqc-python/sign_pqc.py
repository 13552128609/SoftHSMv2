import ctypes

# 1. Load SoftHSM PKCS#11 library
lib = ctypes.CDLL('/usr/local/lib/softhsm/libsofthsm2.so')

# 2. PKCS#11 core types and constants
CK_SESSION_HANDLE = ctypes.c_ulong
CK_OBJECT_HANDLE = ctypes.c_ulong

CKM_ML_DSA_44 = 0x80001001  # CKM_VENDOR_DEFINED(0x80000000) + 0x1001

CKA_CLASS = 0x00000000
CKA_TOKEN = 0x00000001
CKA_LABEL = 0x00000003
CKA_ID = 0x00000102
CKA_SENSITIVE = 0x00000103
CKA_SIGN = 0x00000108
CKA_VERIFY = 0x0000010A
CKA_EXTRACTABLE = 0x00000162
CKA_PARAMETER_SET = 0x0000061D

CKO_PRIVATE_KEY = 0x00000003

CKF_RW_SESSION = 0x00000002
CKF_SERIAL_SESSION = 0x00000004
CKU_USER = 1

# 3. Struct definitions
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


# 4. Initialize library
rv = lib.C_Initialize(None)
if rv not in (0,):
    raise SystemExit(f"C_Initialize failed: 0x{rv:x}")

try:
    # 5. Open session (Slot ID must match generate_pqc.py)
    session = CK_SESSION_HANDLE()
    flags = CKF_RW_SESSION | CKF_SERIAL_SESSION
    slot_id = ctypes.c_ulong(383231617)
    rv = lib.C_OpenSession(slot_id, flags, None, None, ctypes.byref(session))
    if rv != 0:
        raise SystemExit(f"C_OpenSession failed: 0x{rv:x}")

    # 6. Login
    pin = b"123456"
    rv = lib.C_Login(session, CKU_USER, pin, len(pin))
    if rv != 0:
        raise SystemExit(f"C_Login failed: 0x{rv:x}")

    print("[sign_pqc] Logged in, searching for ML-DSA private key ...")

    # 7. Find private key created by generate_pqc.py
    #label = b"Jacob_PQ_Sign_Key"
    label = b"Jacob_PQ_Sign_Key"
    key_id = b"\x00\x01"

# 显式创建变量，锁定内存，防止被 Python 的 GC 自动回收
    obj_class = ctypes.c_ulong(CKO_PRIVATE_KEY)
    label_buffer = ctypes.create_string_buffer(label)
    id_buffer = ctypes.create_string_buffer(key_id)

    attr_class = CK_ATTRIBUTE(CKA_CLASS, ctypes.cast(ctypes.byref(obj_class), ctypes.c_void_p), ctypes.sizeof(obj_class))
    attr_label = CK_ATTRIBUTE(CKA_LABEL, ctypes.cast(label_buffer, ctypes.c_void_p), len(label))
    attr_id = CK_ATTRIBUTE(CKA_ID, ctypes.cast(id_buffer, ctypes.c_void_p), len(key_id))

    template = (CK_ATTRIBUTE * 3)(attr_class, attr_label, attr_id)


    # obj_class = ctypes.c_ulong(CKO_PRIVATE_KEY)
    # attr_class = CK_ATTRIBUTE(CKA_CLASS, ctypes.cast(ctypes.byref(obj_class), ctypes.c_void_p), ctypes.sizeof(obj_class))
    # attr_label = CK_ATTRIBUTE(CKA_LABEL, ctypes.cast(ctypes.create_string_buffer(label), ctypes.c_void_p), len(label))
    # attr_id = CK_ATTRIBUTE(CKA_ID, ctypes.cast(ctypes.create_string_buffer(key_id), ctypes.c_void_p), len(key_id))

    # template = (CK_ATTRIBUTE * 3)(attr_class, attr_label, attr_id)

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
            raise SystemExit("No matching private key found (label/id/class).")
        priv_handle = obj
    finally:
        lib.C_FindObjectsFinal(session)

    print(f"[sign_pqc] Found private key handle: {priv_handle.value}")

    # 8. Prepare data to sign
    message = b"Hello ML-DSA from SoftHSM!"

    # Save message to file
    with open("message.bin", "wb") as f:
        f.write(message)

    # 9. Setup signing mechanism (ML-DSA-44)
    mech = CK_MECHANISM(CKM_ML_DSA_44, None, 0)

    rv = lib.C_SignInit(session, ctypes.byref(mech), priv_handle)
    if rv != 0:
        raise SystemExit(f"C_SignInit failed: 0x{rv:x}")

    # 10. Determine signature length
    sig_len = ctypes.c_ulong(0)
    rv = lib.C_Sign(session, message, len(message), None, ctypes.byref(sig_len))
    if rv != 0:
        raise SystemExit(f"C_Sign (size query) failed: 0x{rv:x}")

    sig_buf = (ctypes.c_ubyte * sig_len.value)()

    rv = lib.C_Sign(session, message, len(message), sig_buf, ctypes.byref(sig_len))
    if rv != 0:
        raise SystemExit(f"C_Sign failed: 0x{rv:x}")

    signature = bytes(sig_buf[: sig_len.value])

    # Save signature to file
    with open("signature.bin", "wb") as f:
        f.write(signature)

    print(f"[sign_pqc] Signature generated, length = {sig_len.value} bytes")
    print("[sign_pqc] message.bin and signature.bin written in current directory")

finally:
    lib.C_Finalize(None)

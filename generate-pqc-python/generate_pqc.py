import ctypes

# 1. 加载 SoftHSM 动态链接库
lib = ctypes.CDLL('/usr/local/lib/softhsm/libsofthsm2.so')

# 2. 定义 PKCS#11 的核心常数
CK_SESSION_HANDLE = ctypes.c_ulong
CK_SLOT_ID = ctypes.c_ulong
CKM_ML_DSA_KEY_PAIR_GEN = 0x0000001C  # 28
CKA_TOKEN = 0x00000001
CKA_LABEL = 0x00000003
CKA_ID = 0x00000102
CKA_SENSITIVE = 0x00000103
CKA_SIGN = 0x00000108
CKA_VERIFY = 0x0000010A
CKA_EXTRACTABLE = 0x00000162
CKA_PARAMETER_SET = 0x0000061D
CKP_ML_DSA_44 = 1
CKF_RW_SESSION = 0x00000002
CKF_SERIAL_SESSION = 0x00000004
CKU_USER = 1

# 属性结构体定义
class CK_ATTRIBUTE(ctypes.Structure):
    _fields_ = [("type", ctypes.c_ulong), ("pValue", ctypes.c_void_p), ("ulValueLen", ctypes.c_ulong)]

class CK_MECHANISM(ctypes.Structure):
    _fields_ = [("mechanism", ctypes.c_ulong), ("pParameter", ctypes.c_void_p), ("ulParameterLen", ctypes.c_ulong)]

# 3. 初始化库
lib.C_Initialize(None)

# 4. 打开会话 (Slot ID: 383231617)
session = CK_SESSION_HANDLE()
flags = CKF_RW_SESSION | CKF_SERIAL_SESSION
res = lib.C_OpenSession(383231617, flags, None, None, ctypes.byref(session))
if res != 0:
    raise Exception(f"打开会话失败，错误码: {hex(res)}")

# 5. 登录 Token
pin = b"123456"
res = lib.C_Login(session, CKU_USER, pin, len(pin))
if res != 0:
    raise Exception(f"登录失败，错误码: {hex(res)}")

print("成功登录 Jacob_PQ_Token，开始通过原始 C 接口指针注入 0x1C 机制...")

# 6. 构造机制与模板
mech = CK_MECHANISM(CKM_ML_DSA_KEY_PAIR_GEN, None, 0)

# 公钥模板 (CKA_TOKEN=True, CKA_VERIFY=True, CKA_LABEL="Jacob_PQ_Sign_Key", CKA_ID=0x0001)
label = b"Jacob_PQ_Sign_Key"
key_id = b"\x00\x01"
true_val = ctypes.c_bool(True)
param_set = ctypes.c_ulong(CKP_ML_DSA_44)

pub_tmpl = (CK_ATTRIBUTE * 5)(
    CK_ATTRIBUTE(CKA_TOKEN, ctypes.cast(ctypes.byref(true_val), ctypes.c_void_p), 1),
    CK_ATTRIBUTE(CKA_VERIFY, ctypes.cast(ctypes.byref(true_val), ctypes.c_void_p), 1),
    CK_ATTRIBUTE(CKA_LABEL, ctypes.cast(ctypes.create_string_buffer(label), ctypes.c_void_p), len(label)),
    CK_ATTRIBUTE(CKA_ID, ctypes.cast(ctypes.create_string_buffer(key_id), ctypes.c_void_p), len(key_id)),
    CK_ATTRIBUTE(CKA_PARAMETER_SET, ctypes.cast(ctypes.byref(param_set), ctypes.c_void_p), ctypes.sizeof(param_set))
)

# 私钥模板 (CKA_TOKEN=True, CKA_SIGN=True, CKA_SENSITIVE=True, CKA_EXTRACTABLE=False)
false_val = ctypes.c_bool(False)
priv_tmpl = (CK_ATTRIBUTE * 6)(
    CK_ATTRIBUTE(CKA_TOKEN, ctypes.cast(ctypes.byref(true_val), ctypes.c_void_p), 1),
    CK_ATTRIBUTE(CKA_SIGN, ctypes.cast(ctypes.byref(true_val), ctypes.c_void_p), 1),
    CK_ATTRIBUTE(CKA_SENSITIVE, ctypes.cast(ctypes.byref(true_val), ctypes.c_void_p), 1),
    CK_ATTRIBUTE(CKA_EXTRACTABLE, ctypes.cast(ctypes.byref(false_val), ctypes.c_void_p), 1),
    CK_ATTRIBUTE(CKA_LABEL, ctypes.cast(ctypes.create_string_buffer(label), ctypes.c_void_p), len(label)),
    CK_ATTRIBUTE(CKA_ID, ctypes.cast(ctypes.create_string_buffer(key_id), ctypes.c_void_p), len(key_id)),
)

# 7. 孕育密钥
pub_handle = ctypes.c_ulong()
priv_handle = ctypes.c_ulong()

res = lib.C_GenerateKeyPair(
    session, 
    ctypes.byref(mech), 
    ctypes.byref(pub_tmpl), 5, 
    ctypes.byref(priv_tmpl), 5, 
    ctypes.byref(pub_handle), 
    ctypes.byref(priv_handle)
)

if res == 0:
    print("🎉 奇迹发生！Raw C 调用成功！")
    print(f"-> ML-DSA-44 密钥对已经在 SoftHSM 安全隔离区内直接生成！")
    print(f"-> 公钥句柄: {pub_handle.value}, 私钥句柄: {priv_handle.value}")
else:
    print(f"❌ 芯片内部生成失败，SoftHSM 返回错误码: {hex(res)}")

# 清理
lib.C_Finalize(None)

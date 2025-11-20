# SHICTHRS JSON Loader

一个功能强大的Python JSON文件加密读写库，支持多种加密算法和完整性验证。

## 特性

- 🔒 **多种加密算法支持**：支持5种不同的加密方式
- 🛡️ **完整性验证**：可选的文件和数据完整性检查
- 🔑 **密钥验证**：自动验证加密密钥的正确性
- 📁 **递归加密**：支持嵌套字典和列表的完整加密
- 🎯 **简单易用**：简洁的API接口设计

## 安装

```bash
pip install SHICTHRSJsonLoader
```

## 依赖

- Python 3.6+
- colorama==0.4.6
- pycryptodome==3.23.0

## API接口

### 读取JSON文件

```python
from SHICTHRSJsonLoader import SHRJsonLoader_read_json_file

# 读取普通JSON文件
data = SHRJsonLoader_read_json_file('data.json')

# 读取加密的JSON文件
data = SHRJsonLoader_read_json_file('encrypted_data.json', ectype='b0', key='your_secret_key')

# 带完整性验证的读取
data = SHRJsonLoader_read_json_file('secure_data.json', ectype='b0', key='your_secret_key', verify=True)
```

### 写入JSON文件

```python
from SHICTHRSJsonLoader import SHRJsonLoader_write_json_file

# 写入普通JSON文件
SHRJsonLoader_write_json_file({'key': 'value'}, 'data.json')

# 写入加密的JSON文件
SHRJsonLoader_write_json_file({'key': 'value'}, 'encrypted_data.json', ectype='b0', key='your_secret_key')

# 带完整性验证的写入
SHRJsonLoader_write_json_file({'key': 'value'}, 'secure_data.json', ectype='b0', key='your_secret_key', verify=True)
```

### 参数说明

- `path`: JSON文件路径
- `ectype`: 加密类型（可选：'b0', 'b1', 'b2', 'b3', 'b4' 或 None）
- `key`: 加密密钥（使用加密时必填）
- `verify`: 是否启用完整性验证（默认为False）

## 加密方法介绍

### b0 - ChaCha20-Poly1305 认证加密
- **算法**: ChaCha20流密码 + Poly1305消息认证码
- **安全性**: 高
- **特点**: 提供认证加密，防止数据篡改
- **密钥派生**: SHA256哈希

### b1 - ChaCha20 流加密
- **算法**: ChaCha20流密码
- **安全性**: 中高
- **特点**: 高性能流加密
- **密钥派生**: SHA256哈希

### b2 - AES-CBC 块加密
- **算法**: AES-CBC模式
- **安全性**: 高
- **特点**: 标准块加密，支持PKCS7填充
- **密钥派生**: SHA256哈希

### b3 - HMAC-SHA256 认证
- **算法**: HMAC-SHA256
- **安全性**: 中
- **特点**: 消息认证码，验证数据完整性
- **密钥派生**: SHA256哈希

### b4 - XOR 异或加密
- **算法**: 简单异或操作
- **安全性**: 低
- **特点**: 轻量级加密，性能最佳
- **密钥派生**: 直接使用密钥

## 使用示例

### 基本使用

```python
from SHICTHRSJsonLoader import SHRJsonLoader_read_json_file, SHRJsonLoader_write_json_file

# 写入加密数据
data = {
    'username': 'admin',
    'password': 'secret123',
    'settings': {
        'theme': 'dark',
        'language': 'zh-CN'
    }
}

SHRJsonLoader_write_json_file(data, 'config.json', ectype='b0', key='my_secret_key', verify=True)

# 读取加密数据
config = SHRJsonLoader_read_json_file('config.json', ectype='b0', key='my_secret_key', verify=True)
print(config)
```

### 错误处理

```python
from SHICTHRSJsonLoader import SHRJsonLoader_read_json_file, SHRJsonLoaderException

try:
    data = SHRJsonLoader_read_json_file('config.json', ectype='b0', key='wrong_key', verify=True)
except SHRJsonLoaderException as e:
    print(f"读取文件失败: {e}")
```

## 错误代码

| 错误代码 | 描述 |
|---------|------|
| ERROR.1004 | 不支持的文件类型 |
| ERROR.1005 | 文件未找到 |
| ERROR.1006 | 读取JSON文件失败 |
| ERROR.1007 | 不支持的文件类型（写入） |
| ERROR.1008 | 写入JSON文件失败 |
| ERROR.1009 | 加密密钥未提供 |
| ERROR.1010 | 无效的加密文件 |
| ERROR.1011 | 错误的加密密钥 |
| ERROR.1012 | 数据完整性检查失败 |
| ERROR.1013 | 不支持的加密类型 |
| ERROR.1014 | 加密类型不匹配 |
| ERROR.1015 | 参数类型错误 |
| ERROR.1016 | 文件完整性检查失败 |

## 项目结构

```
SHICTHRSJsonLoader/
├── SHICTHRSJsonLoader/
│   ├── __init__.py              # 主模块入口
│   └── utils/
│       ├── json/
│       │   ├── SHRJsonLoader_read_json_file.py    # 读取功能
│       │   └── SHRJsonLoader_write_json_file.py   # 写入功能
│       ├── hash/
│       │   └── SHRJsonLoader_en_md5_hexdigest.py  # MD5哈希
│       └── base64/
│           ├── SHRJsonLoader_de_base64.py        # Base64解码
│           └── SHRJsonLoader_en_base64.py        # Base64编码
├── setup.py                     # 安装配置
└── README.md                    # 项目文档
```

## 许可证

本项目采用 GPL-3.0 许可证。详见 [LICENSE](LICENSE) 文件。

## 贡献

欢迎提交 Issue 和 Pull Request！

## 作者

- **SHICTHRS** - [GitHub](https://github.com/JNTMTMTM)

## 版权声明

© 2025-2026 SHICTHRS, Std. All rights reserved.
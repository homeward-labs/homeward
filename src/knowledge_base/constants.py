"""知识库内容源配置 —— 所有「可能变动」的项集中在此，变更只改这里。

涵盖：默认源地址、本地目录名、内容源中各文件命名、验签相关文件名、产品主页等。
客户端其它模块（engine / attribution / device / main）与内容源更新器（updater）
均从此处导入，避免散落硬编码字符串。

变更约定：
  - 换内容源地址 → 改 ``KB_SOURCE_DEFAULT_URL``
  - 改任意文件名 / 目录名 → 改对应 ``*_FILE`` / ``*_DIR_NAME``
  - 换产品主页 → 改 ``USER_AGENT_HOMEPAGE``
无需改动任何业务逻辑代码。
"""
from __future__ import annotations

# 内容源（Cloudflare Worker / 内网镜像）默认地址。
# 客户端知识库更新器的兜底源；可用环境变量 HOMEWARD_KB_SOURCE 覆盖。
KB_SOURCE_DEFAULT_URL = "https://homeward-kb.782238788.workers.dev"

# 知识库在客户端本地所处的目录名（相对 src 根）。
KB_DIR_NAME = "knowledge_base"

# 内容源中的文件名（变更文件名只需改这里）
VERSION_FILE = "VERSION"
CHECKSUM_FILE = "CHECKSUM"
SIGNATURE_FILE = "SIGNATURE"
LICENSE_FILE = "LICENSE"
DOMAINS_CSV = "domains.csv"
BEHAVIORS_JSON = "behaviors.json"
OUI_PREFIXES_CSV = "oui_prefixes.csv"
ASN_CSV = "asn.csv"

# 验签相关
KB_LICENSE_DIRNAME = "license"
KB_PUBKEY_FILENAME = "kb_pubkey.txt"
ED25519_MODULE_BASENAME = "ed25519.py"

# 产品主页（仅用于 User-Agent 标识，不含任何隐私数据）
USER_AGENT_HOMEPAGE = "https://github.com/homeward-labs/homeward"

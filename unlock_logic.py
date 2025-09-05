# append_values.py — Nhập cURL để cập nhật token/cookies tức thời + gọi API + chẩn đoán
from pathlib import Path
import re
import json
import argparse
import uuid
import unicodedata
import base64
import time
import sys
from typing import List, Optional, Tuple, Dict

try:
    import requests
except ImportError:
    raise SystemExit("Thiếu thư viện 'requests'. Cài: pip install requests")

# ==================== CONFIGURATION ====================
class Config:
    """Lớp chứa tất cả các hằng số cấu hình."""
    try:
        BASE_DIR = Path(__file__).parent
    except NameError:
        BASE_DIR = Path.cwd()

    # --- Paths ---
    STORE_PATH = BASE_DIR / "values_store.txt"
    AUTH_STORE_PATH = BASE_DIR / "auth_store.json"

    # --- API Defaults ---
    DEFAULT_URL = "https://quatetdoclap.dancuquocgia.gov.vn/asxh/api/v1/user/unlock-account"
    DEFAULT_AUTH = ""
    DEFAULT_COOKIES = ""
    DEFAULT_LY_DO = "mo khoa tai khoan cho cong an dia phuong"

    # --- Regex Patterns ---
    VALUE_REGEX = re.compile(r'\b([a-z0-9]+)_(\d+)_([a-z0-9]+)_(\d+)_([a-z0-9]+)\b')
    # cURL parsing regex
    _HDR_RE = re.compile(r"-H\s+(?:'([^']*)'|\"([^\"]*)\")")
    _B_RE = re.compile(r"-b\s+\$?'([^']*)'|-b\s+\"([^\"]*)\"|-b\s+([^\s]+)")
    _URL_RE = re.compile(r"^curl\s+(?:'([^']+)'|\"([^\"]+)\"|(\S+))", re.IGNORECASE)

# ==================== STORAGE MANAGER ====================
class StorageManager:
    """Quản lý tất cả các hoạt động I/O file."""
    def __init__(self, config: Config):
        self.config = config

    def load_values(self) -> List[str]:
        """Tải danh sách values từ file."""
        if not self.config.STORE_PATH.exists():
            return []
        text = self.config.STORE_PATH.read_text(encoding="utf-8").strip()
        if not text:
            return []
        parts = re.split(r'[;\r\n]+', text)
        seen = set()
        out: List[str] = []
        for p in parts:
            v = p.strip()
            if v and v not in seen:
                seen.add(v)
                out.append(v)
        return out

    def save_values(self, values: List[str]) -> None:
        """Lưu danh sách values vào file."""
        self.config.STORE_PATH.write_text("\n".join(values), encoding="utf-8")

    def save_auth(self, url: str, auth: str, cookies: str) -> None:
        """Lưu thông tin auth (URL, token, cookies) vào file JSON."""
        auth_data = {"url": url, "auth": auth, "cookies": cookies}
        self.config.AUTH_STORE_PATH.write_text(json.dumps(auth_data, ensure_ascii=False, indent=2), encoding="utf-8")

    def load_auth(self) -> Tuple[str, str, str]:
        """Tải thông tin auth từ file JSON."""
        if self.config.AUTH_STORE_PATH.exists():
            try:
                data = json.loads(self.config.AUTH_STORE_PATH.read_text(encoding="utf-8"))
                return (
                    data.get("url", self.config.DEFAULT_URL),
                    data.get("auth", self.config.DEFAULT_AUTH),
                    data.get("cookies", self.config.DEFAULT_COOKIES)
                )
            except (json.JSONDecodeError, IOError):
                pass
        return self.config.DEFAULT_URL, self.config.DEFAULT_AUTH, self.config.DEFAULT_COOKIES

    @staticmethod
    def extract_tokens(text: str) -> List[str]:
        """Trích xuất tất cả các chuỗi token hợp lệ từ một khối văn bản."""
        return ["_".join(m) for m in Config.VALUE_REGEX.findall(text)]

    @staticmethod
    def print_outputs(values: List[str], ly_do: str) -> None:
        """In payload JSON và danh sách user theo định dạng yêu cầu."""
        payload = {"lstUserName": values, "lyDo": ly_do}
        print(json.dumps(payload, ensure_ascii=False, separators=(",", ":")))
        print(";".join(values))

# ==================== UTILITIES ====================
class Utils:
    """Lớp chứa các hàm tiện ích tĩnh."""

    @staticmethod
    def _unescape_bash_dollar_string(s: str) -> str:
        """Xử lý chuỗi bash $'...' (ví dụ: $'\\uXXXX')."""
        def repl(m):
            return chr(int(m.group(1), 16))
        s = re.sub(r"\\u([0-9a-fA-F]{4})", repl, s)
        s = s.replace("\\n", "\n").replace("\\t", "\t").replace("\\'", "'").replace('\\"', '"').replace("\\\\", "\\")
        return s

    @staticmethod
    def parse_curl(curl_text: str) -> Tuple[Optional[str], Optional[str], Optional[str]]:
        """Phân tích chuỗi cURL để trích xuất URL, Authorization header và Cookies."""
        url = auth = cookies = None

        # URL
        m = Config._URL_RE.search(curl_text.strip().splitlines()[0])
        if m:
            url = next((g for g in m.groups() if g), None)

        # Headers from -H
        for hm in Config._HDR_RE.finditer(curl_text):
            h = hm.group(1) or hm.group(2) or ""
            parts = h.split(":", 1)
            if len(parts) == 2:
                key, val = parts[0].strip().lower(), parts[1].strip()
                if key == "authorization":
                    auth = val
                elif key == "cookie":
                    cookies = val

        # Cookies from -b
        bm = Config._B_RE.search(curl_text)
        if bm:
            bval = next((g for g in bm.groups() if g), "")
            if bval.startswith("$'") and bval.endswith("'"):
                bval = bval[2:-1]
            cookies_b = Utils._unescape_bash_dollar_string(bval)
            cookies = f"{cookies}; {cookies_b}" if cookies else cookies_b

        return url, auth, cookies

    @staticmethod
    def jwt_exp_left(auth_header: str) -> Optional[int]:
        """Trả về số giây còn lại nếu auth_header là 'Bearer <jwt>'."""
        if not auth_header or not auth_header.lower().startswith("bearer "):
            return None
        try:
            token = auth_header.split(None, 1)[1]
            payload_b64 = token.split(".")[1]
            padding = '=' * (-len(payload_b64) % 4)
            payload = json.loads(base64.urlsafe_b64decode(payload_b64 + padding))
            exp = int(payload["exp"])
            return exp - int(time.time())
        except (IndexError, KeyError, Exception):
            return None

    @staticmethod
    def fmt_exp_left(auth_header: str) -> str:
        """Định dạng thời gian hết hạn token thành chuỗi thân thiện."""
        seconds = Utils.jwt_exp_left(auth_header)
        if seconds is None:
            return "(không đọc được hạn token)"
        if seconds < 0:
            return f"(đã hết hạn {abs(seconds)//60} phút)"
        return f"(còn ~{seconds//60} phút)"

    @staticmethod
    def extract_tokens(text: str) -> List[str]:
        """Trích xuất tất cả các chuỗi token hợp lệ từ một khối văn bản."""
        return ["_".join(m) for m in Config.VALUE_REGEX.findall(text)]

    @staticmethod
    def print_outputs(values: List[str], ly_do: str) -> None:
        """In payload JSON và danh sách user theo định dạng yêu cầu."""
        payload = {"lstUserName": values, "lyDo": ly_do}
        print(json.dumps(payload, ensure_ascii=False, separators=(",", ":")))
        print(";".join(values))

# ==================== API CLIENT ====================
class ApiClient:
    """Xử lý tất cả các giao tiếp HTTP với API."""
    def __init__(self, auth_header: Optional[str], cookies_str: Optional[str]):
        self.session = self._build_session(auth_header, cookies_str)

    def _build_session(self, auth_header: Optional[str], cookies_str: Optional[str]) -> requests.Session:
        """Xây dựng và cấu hình một session requests."""
        s = requests.Session()
        headers = {
            "Accept": "*/*",
            "Content-Type": "application/json",
            "User-Agent": f"ValuesInlineClient/1.0 (Python/{sys.version_info.major}.{sys.version_info.minor})",
            "x-client-request-id": str(uuid.uuid4()),
        }
        if auth_header:
            headers["Authorization"] = auth_header
        if cookies_str:
            headers["Cookie"] = cookies_str
        s.headers.update(headers)
        return s

    def post_unlock(self, url: str, users: List[str], ly_do: str, timeout: int = 30) -> Tuple[int, any]:
        """Gửi request POST để mở khóa tài khoản."""
        payload = {"lstUserName": users, "lyDo": ly_do}
        try:
            resp = self.session.post(url, json=payload, timeout=timeout)
            data = resp.json()
        except requests.exceptions.JSONDecodeError:
            data = resp.text
        except requests.exceptions.RequestException as e:
            return 500, str(e)
        return resp.status_code, data

    @staticmethod
    def _remove_accents(s: str) -> str:
        """Loại bỏ dấu tiếng Việt khỏi chuỗi."""
        return "".join(c for c in unicodedata.normalize("NFD", s) if unicodedata.category(c) != "Mn")

    def _resp_contains_not_exist(self, data: any) -> bool:
        """Kiểm tra xem response có chứa thông báo 'không tồn tại' hay không."""
        text = data if isinstance(data, str) else json.dumps(data, ensure_ascii=False)
        t = self._remove_accents(text).lower()
        return ("khong ton tai" in t) or ("tai khoan khong ton tai" in t)

    def diagnose_not_found(self, url: str, ly_do: str, users: List[str], timeout: int = 30) -> List[str]:
        """Chẩn đoán đệ quy để tìm các tài khoản không tồn tại."""
        not_found: List[str] = []

        def _recurse(group: List[str]):
            if not group:
                return
            status, data = self.post_unlock(url, group, ly_do, timeout=timeout)
            print(f"    · Check {len(group)} user | HTTP {status}")
            if not self._resp_contains_not_exist(data):
                return
            if len(group) == 1:
                not_found.append(group[0])
                return
            mid = len(group) // 2
            _recurse(group[:mid])
            _recurse(group[mid:])

        _recurse(users)
        return not_found

# ==================== APPLICATION ====================
class ApiUnlockTool:
    """Lớp ứng dụng chính điều khiển logic tương tác."""
    def __init__(self, args):
        self.config = Config()
        self.storage = StorageManager(self.config)
        self.should_store = not args.no_store
        self.timeout = args.timeout
        self.chunk_size = args.chunk_size

        # State
        self.values: List[str] = [] if (args.clear or not self.should_store) else self.storage.load_values()
        self.seen: set = set(self.values)
        self.ly_do: str = args.lydo or self.config.DEFAULT_LY_DO
        self.url, self.auth, self.cookies = self.storage.load_auth()
        self.last_new_tokens: List[str] = []
        self.api_client: Optional[ApiClient] = None

    def _get_api_client(self) -> Optional[ApiClient]:
        """Khởi tạo hoặc trả về ApiClient nếu có thông tin auth."""
        if not self.auth:
            print("❌ Chưa có Authorization/Cookies. Dùng /auth để dán cURL.")
            return None
        if self.api_client is None:
            self.api_client = ApiClient(self.auth, self.cookies)
        return self.api_client

    def _handle_auth(self):
        """Xử lý lệnh /auth để cập nhật cURL."""
        print("Dán FULL cURL (có Authorization và -b cookies), kết thúc bằng 'END':")
        buf = []
        while True:
            try:
                line = input()
                if line.strip().upper() == 'END':
                    break
                buf.append(line)
            except EOFError:
                break
        curl_text = "\n".join(buf)
        new_url, new_auth, new_cookies = Utils.parse_curl(curl_text)

        self.url = new_url or self.url
        self.auth = new_auth or self.auth
        self.cookies = new_cookies or self.cookies
        self.storage.save_auth(self.url, self.auth, self.cookies)
        self.api_client = None  # Force rebuild on next API call
        print(f"✅ Đã cập nhật AUTH/COOKIES. {Utils.fmt_exp_left(self.auth)}")

    def _handle_auth_show(self):
        """Xử lý lệnh /authshow để hiển thị thông tin auth."""
        print(f"URL: {self.url}")
        tok = self.auth.split()[-1] if self.auth else ''
        tail = f"...{tok[-16:]}" if tok else ''
        auth_status = 'Bearer ...' if self.auth else '(chưa có)'
        print(f"Auth: {auth_status} {tail} {Utils.fmt_exp_left(self.auth)}")
        print(f"Cookies: {'(đã nạp)' if self.cookies else '(chưa có)'}")

    def _handle_clear(self):
        """Xử lý lệnh /clear để xóa danh sách."""
        self.values.clear()
        self.seen.clear()
        self.last_new_tokens = []
        if self.should_store:
            self.storage.save_values(self.values)
        print("Đã xóa danh sách.")

    def _handle_lydo(self, line: str):
        """Xử lý lệnh /lydo để cập nhật lý do."""
        new_reason = line.partition(" ")[2].strip()
        if not new_reason:
            try:
                new_reason = input("Nhập ly do mới: ").strip()
            except EOFError:
                pass
        if new_reason:
            self.ly_do = new_reason
            print(f"Đã cập nhật lyDo: {self.ly_do}")
        else:
            print("Giữ nguyên lyDo hiện tại.")

    def _execute_api_call(self, scope: str, action: str):
        """Thực thi logic gọi API cho /call và /diag."""
        target_users = self.last_new_tokens if scope == "new" else self.values
        if not target_users:
            print(f"Không có user để {action}.")
            return

        client = self._get_api_client()
        if not client:
            return

        if action == 'call':
            batches = [target_users] if self.chunk_size <= 0 else [target_users[i:i+self.chunk_size] for i in range(0, len(target_users), self.chunk_size)]
            print(f"🔔 Gọi API: {self.url} | lô: {len(batches)} | tổng user: {len(target_users)} | phạm vi: {scope.upper()}")
            for idx, batch in enumerate(batches, 1):
                status, data = client.post_unlock(self.url, batch, self.ly_do, self.timeout)
                print(f"  - Lô {idx}/{len(batches)} | {len(batch)} user | HTTP {status}")
                print(f"    {json.dumps(data, ensure_ascii=False)}")
                if status in (401, 403):
                    print("⚠️ Có thể token đã hết hạn. Dán cURL mới với lệnh /auth rồi chạy lại.")
                    break
        elif action == 'diag':
            print(f"🔎 Chuẩn đoán (divide-and-conquer) {len(target_users)} user | phạm vi: {scope.upper()}")
            not_found = client.diagnose_not_found(self.url, self.ly_do, target_users, self.timeout)
            result = {"tested": len(target_users), "notFoundCount": len(not_found), "notFound": not_found}
            print("Kết quả chẩn đoán:")
            print(json.dumps(result, ensure_ascii=False, separators=(",", ":")))

    def _handle_end_input(self, lines: List[str]):
        """Xử lý khi người dùng nhập 'END'."""
        blob = "\n".join(lines)
        # Trích xuất tất cả các token hợp lệ từ khối nhập liệu gần nhất
        tokens_from_last_input = Utils.extract_tokens(blob)
        self.last_new_tokens = tokens_from_last_input  # Luôn cập nhật danh sách token mới nhất

        added = 0
        # Chỉ thêm những token chưa từng thấy vào danh sách chính
        for t in tokens_from_last_input:
            if t not in self.seen:
                self.values.append(t)
                self.seen.add(t)
                added += 1

        if self.should_store and added > 0:
            self.storage.save_values(self.values)

        print(f"Phát hiện {len(tokens_from_last_input)} hợp lệ, thêm mới {added}. Tổng hiện có: {len(self.values)}")
        Utils.print_outputs(self.values, self.ly_do)
        print("\n(Dán tiếp và gõ END; dùng /call [new|all]; /diag [new|all]; /auth để cập nhật cURL; /q thoát)")

    def run(self):
        """Chạy vòng lặp tương tác chính."""
        print("Dán danh sách value, kết thúc đợt bằng 'END' (in JSON + ';').")
        print("Lệnh: /auth, /authshow, /show, /clear, /lydo <text>, /call [all|new], /diag [all|new], /q\n")
        lines: List[str] = []
        while True:
            try:
                line = input()
                s = line.strip()
                if not s:
                    continue
                cmd = s.lower().split(maxsplit=1)[0]

                if cmd == "/auth": self._handle_auth()
                elif cmd == "/authshow": self._handle_auth_show()
                elif cmd == "/show": Utils.print_outputs(self.values, self.ly_do)
                elif cmd == "/clear": self._handle_clear()
                elif cmd == "/lydo": self._handle_lydo(s)
                elif cmd in ("/q", "done"): break
                elif cmd == "/call":
                    scope = s.split(maxsplit=1)[1].strip().lower() if len(s.split()) > 1 else "new"
                    self._execute_api_call(scope if scope in ('new', 'all') else 'new', 'call')
                elif cmd == "/diag":
                    scope = s.split(maxsplit=1)[1].strip().lower() if len(s.split()) > 1 else "new"
                    self._execute_api_call(scope if scope in ('new', 'all') else 'new', 'diag')
                elif s.upper() == "END":
                    self._handle_end_input(lines)
                    lines = []
                else:
                    lines.append(line)
            except EOFError:
                break
            except KeyboardInterrupt:
                break

# ==================== MAIN ====================
def main():
    """Entry point chính của script."""
    parser = argparse.ArgumentParser(
        description="Dán đợt -> END (in JSON + ';'); /auth để dán cURL cập nhật token/cookies; /call để mở TK; /diag để truy TK không tồn tại",
        formatter_class=argparse.RawTextHelpFormatter
    )
    parser.add_argument("--lydo", type=str, default=None, help="Nội dung trường lyDo ban đầu")
    parser.add_argument("--clear", action="store_true", help="Xóa danh sách trước khi bắt đầu")
    parser.add_argument("--no-store", action="store_true", help="Không lưu tích lũy vào values_store.txt")
    parser.add_argument("--timeout", type=int, default=30, help="Timeout mỗi request (giây)")
    parser.add_argument("--chunk-size", type=int, default=0, help="Số user mỗi request khi /call (0 = không chia)")
    args = parser.parse_args()

    tool = ApiUnlockTool(args)
    tool.run()

if __name__ == "__main__":
    main()

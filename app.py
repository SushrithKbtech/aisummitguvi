import os
import re
import json
import logging
import uuid
from typing import List, Optional, Dict, Any
from urllib.parse import parse_qs

import requests
from fastapi import FastAPI, Header, HTTPException, BackgroundTasks, Body, Request
from pydantic import BaseModel, Field
from pydantic import ConfigDict

try:
    from openai import OpenAI
except Exception:  # pragma: no cover - optional for local runs
    OpenAI = None


APP_NAME = "agentic-honeypot"

API_KEY = os.getenv("API_KEY")
OPENAI_API_KEY = os.getenv("OPENAI_API_KEY")
OPENAI_MODEL = os.getenv("OPENAI_MODEL", "gpt-4o-mini")
USE_LLM_REPLY = os.getenv("USE_LLM_REPLY", "true").lower() == "true"
USE_LLM_EXTRACTION = os.getenv("USE_LLM_EXTRACTION", "true").lower() == "true"
USE_LLM_CLASSIFIER = os.getenv("USE_LLM_CLASSIFIER", "true").lower() == "true"

GUVI_CALLBACK_URL = os.getenv(
    "GUVI_CALLBACK_URL",
    "https://hackathon.guvi.in/api/updateHoneyPotFinalResult",
)


def get_int_env(name: str, default: str) -> int:
    value = os.getenv(name, default)
    try:
        return int(value)
    except ValueError:
        return int(default)


MAX_SCAMMER_MESSAGES = get_int_env("MAX_SCAMMER_MESSAGES", "0")
MAX_TOTAL_MESSAGES = get_int_env("MAX_TOTAL_MESSAGES", "0")

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(APP_NAME)
for noisy_logger in ("httpx", "openai", "urllib3"):
    logging.getLogger(noisy_logger).setLevel(logging.WARNING)

client = None
if OPENAI_API_KEY and OpenAI:
    client = OpenAI(api_key=OPENAI_API_KEY)


class Message(BaseModel):
    sender: str
    text: str
    timestamp: Optional[str] = None


class Metadata(BaseModel):
    channel: Optional[str] = None
    language: Optional[str] = None
    locale: Optional[str] = None


class IncomingRequest(BaseModel):
    model_config = ConfigDict(populate_by_name=True, extra="ignore")
    sessionId: str = Field(..., alias="sessionId")
    message: Message
    conversationHistory: List[Message] = Field(default_factory=list)
    metadata: Optional[Metadata] = None


app = FastAPI(title=APP_NAME)


INTEL_FIELDS = [
    "bankAccounts",
    "upiIds",
    "phishingLinks",
    "phoneNumbers",
    "employeeIds",
    "orgNames",
    "suspiciousKeywords",
    "accountLast4",
    "complaintIds",
    "callbackNumbers",
    "emailAddresses",
    "appNames",
    "transactionIds",
    "merchantNames",
    "amounts",
    "ifscCodes",
    "departmentNames",
    "designations",
    "supervisorNames",
    "scammerNames",
]

SLOT_PRIORITY = [
    "orgNames",
    "departmentNames",
    "designations",
    "employeeIds",
    "callbackNumbers",
    "emailAddresses",
    "phishingLinks",
    "complaintIds",
    "transactionIds",
    "upiIds",
    "bankAccounts",
    "ifscCodes",
    "merchantNames",
    "appNames",
    "amounts",
    "supervisorNames",
    "scammerNames",
    "accountLast4",
]

SLOT_KEYWORDS = {
    "bankAccounts": ["account number", "bank account", "a/c", "acct"],
    "upiIds": ["upi", "vpa"],
    "phishingLinks": ["link", "url", "website", "portal", "download link"],
    "phoneNumbers": ["phone", "call", "number", "mobile"],
    "employeeIds": ["employee id", "agent id", "staff id", "agent number"],
    "orgNames": ["bank", "organization", "company", "branch"],
    "accountLast4": ["last 4", "ending", "last four"],
    "complaintIds": ["complaint", "reference", "ref", "ticket", "case id"],
    "callbackNumbers": ["callback", "call back", "call-back", "helpline"],
    "emailAddresses": ["email", "mail"],
    "appNames": ["app", "application", "apk", "download", "install", "anydesk", "teamviewer"],
    "transactionIds": ["transaction id", "txn", "utr", "rrn"],
    "merchantNames": ["merchant", "beneficiary"],
    "amounts": ["amount", "fee", "charge", "pay"],
    "ifscCodes": ["ifsc"],
    "departmentNames": ["department", "desk", "cell", "fraud team"],
    "designations": ["designation", "role", "position"],
    "supervisorNames": ["supervisor", "manager", "team lead"],
    "scammerNames": ["name", "who am i speaking to"],
}

FALLBACK_RESPONSES = {
    "employeeIds": "I can't share any OTP or PIN. What is your employee ID?",
    "callbackNumbers": "I won't share details over chat. What's the official callback number?",
    "emailAddresses": "Please send the official email address for verification.",
    "phishingLinks": "Can you share the official website link where I should verify this?",
    "complaintIds": "Can you share the complaint or reference ID for this case?",
    "orgNames": "Which bank or organization are you calling from?",
    "departmentNames": "Which department is handling this?",
    "designations": "What's your designation there?",
    "upiIds": "If a verification fee is needed, please share the UPI ID.",
    "bankAccounts": "Which account number should I use for the verification?",
    "ifscCodes": "Please share the IFSC code for the account.",
    "transactionIds": "Is there a transaction or UTR reference I should note?",
    "scammerNames": "May I have your full name?",
    "supervisorNames": "Who is your supervisor I can verify with?",
    "appNames": "Which app should I use to complete this?",
    "merchantNames": "Who is the beneficiary/merchant name?",
    "amounts": "How much is the verification amount?",
    "accountLast4": "Which account is this, can you share the last 4 digits?",
    "phoning": "What's the best number to call you back on?",
}

UPI_HANDLES = {
    "upi",
    "ybl",
    "okicici",
    "okhdfc",
    "okaxis",
    "okbizaxis",
    "oksbi",
    "okyes",
    "paytm",
    "apl",
    "axl",
    "icici",
    "sbi",
    "ibl",
    "airtel",
    "jio",
    "fbl",
    "pnb",
    "boi",
    "kotak",
    "idfc",
    "hsbc",
    "barodampay",
    "mahb",
    "indus",
    "cnrb",
    "yesbank",
    "okidbi",
    "okboi",
}

SUSPICIOUS_KEYWORDS = [
    "urgent",
    "immediately",
    "account blocked",
    "account will be blocked",
    "account suspension",
    "account suspended",
    "account compromised",
    "verify",
    "verification",
    "otp",
    "pin",
    "password",
    "kyc",
    "kyc update",
    "pan",
    "aadhaar",
    "aadhar",
    "suspension",
    "suspended",
    "blocked",
    "block",
    "secure",
    "refund",
    "cashback",
    "income tax refund",
    "prize",
    "lottery",
    "processing fee",
    "gift",
    "reward",
    "limited time",
    "click",
    "link",
    "download",
    "install",
    "apk",
    "remote access",
    "anydesk",
    "teamviewer",
    "quicksupport",
    "sim swap",
    "duplicate sim",
    "upi",
    "transfer",
    "pay",
    "bank",
    "loan",
    "credit card",
    "debit card",
    "police",
    "income tax",
    "customs",
    "fraud prevention",
    "verification team",
    "fraudulent transaction",
    "transaction",
    "fraud",
]

DETECTION_KEYWORDS = [
    "urgent",
    "immediately",
    "account blocked",
    "account will be blocked",
    "otp",
    "pin",
    "password",
    "kyc",
    "verification",
    "refund",
    "prize",
    "lottery",
    "apk",
    "remote access",
    "upi",
    "bank",
    "fraud",
    "income tax",
    "sim swap",
]

ORG_KEYWORDS = {
    "sbi": "SBI",
    "state bank of india": "SBI",
    "hdfc": "HDFC Bank",
    "icici": "ICICI Bank",
    "axis": "Axis Bank",
    "kotak": "Kotak Bank",
    "pnb": "Punjab National Bank",
    "union bank": "Union Bank",
    "canara": "Canara Bank",
    "bank of baroda": "Bank of Baroda",
    "bob": "Bank of Baroda",
    "idfc": "IDFC Bank",
    "yes bank": "Yes Bank",
    "indusind": "IndusInd Bank",
    "rbi": "RBI",
    "income tax": "Income Tax Department",
    "it department": "Income Tax Department",
}

DEPARTMENT_KEYWORDS = {
    "fraud prevention": "Fraud Prevention",
    "fraud department": "Fraud Department",
    "fraud cell": "Fraud Cell",
    "kyc": "KYC",
    "verification": "Verification",
    "security": "Security",
    "risk": "Risk",
    "compliance": "Compliance",
    "cyber crime": "Cyber Crime",
}

REMOTE_APP_KEYWORDS = {
    "anydesk": "AnyDesk",
    "teamviewer": "TeamViewer",
    "quick support": "QuickSupport",
    "quicksupport": "QuickSupport",
    "zoho assist": "Zoho Assist",
    "airdroid": "AirDroid",
    "remote desktop": "Remote Desktop",
}

TERMINATION_KEYWORDS = [
    "final notice",
    "last chance",
    "last warning",
    "case closed",
    "no response",
    "final reminder",
]

CORE_INTEL_FIELDS = [
    "orgNames",
    "departmentNames",
    "employeeIds",
    "scammerNames",
    "callbackNumbers",
    "phoneNumbers",
    "emailAddresses",
    "phishingLinks",
    "upiIds",
    "bankAccounts",
    "ifscCodes",
    "transactionIds",
    "merchantNames",
    "amounts",
    "appNames",
    "complaintIds",
]


def empty_intelligence() -> Dict[str, List[str]]:
    return {field: [] for field in INTEL_FIELDS}


def normalize_list(values: List[str]) -> List[str]:
    seen = set()
    normalized = []
    for value in values:
        value = value.strip()
        if not value:
            continue
        key = value.lower()
        if key in seen:
            continue
        seen.add(key)
        normalized.append(value)
    return normalized


def extract_regex_items(text: str) -> Dict[str, List[str]]:
    findings: Dict[str, List[str]] = {field: [] for field in INTEL_FIELDS}
    lower = text.lower()

    for keyword in SUSPICIOUS_KEYWORDS:
        pattern = re.compile(re.escape(keyword), re.IGNORECASE)
        match = pattern.search(text)
        if match:
            findings["suspiciousKeywords"].append(match.group(0))

    for keyword, org in ORG_KEYWORDS.items():
        if keyword in lower:
            findings["orgNames"].append(org)

    for keyword, department in DEPARTMENT_KEYWORDS.items():
        if keyword in lower:
            findings["departmentNames"].append(department)

    for keyword, app in REMOTE_APP_KEYWORDS.items():
        if keyword in lower:
            findings["appNames"].append(app)

    url_pattern = re.compile(r"https?://[^\s]+", re.IGNORECASE)
    findings["phishingLinks"].extend(url_pattern.findall(text))

    email_pattern = re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b")
    for email in email_pattern.findall(text):
        findings["emailAddresses"].append(email)

    apk_pattern = re.compile(r"\b[\w\-]{2,}\.apk\b", re.IGNORECASE)
    for apk in apk_pattern.findall(text):
        findings["appNames"].append(apk)

    branch_pattern = re.compile(r"\b([A-Za-z]+)\s+branch\b", re.IGNORECASE)
    for match in branch_pattern.finditer(text):
        phrase = match.group(0)
        location = match.group(1)
        if phrase:
            findings["orgNames"].append(phrase)
        if location:
            findings["orgNames"].append(location)

    upi_pattern = re.compile(r"\b[\w.\-]{2,}@[A-Za-z0-9]{2,}\b")
    for candidate in upi_pattern.findall(text):
        handle = candidate.split("@", 1)[-1].lower()
        if handle in UPI_HANDLES or handle.startswith("ok") or handle.endswith("upi"):
            findings["upiIds"].append(candidate)

    ifsc_pattern = re.compile(r"\b[A-Z]{4}0[A-Z0-9]{6}\b")
    findings["ifscCodes"].extend(ifsc_pattern.findall(text))

    phone_pattern = re.compile(r"(?:\+?\d[\d\s\-]{7,}\d)")
    for raw in phone_pattern.findall(text):
        digits = re.sub(r"\D", "", raw)
        if 8 <= len(digits) <= 15:
            normalized = "+" + digits if raw.strip().startswith("+") else digits
            findings["phoneNumbers"].append(normalized)
            if any(keyword in lower for keyword in ["callback", "call back", "call-back", "helpline"]):
                findings["callbackNumbers"].append(normalized)

    account_pattern = re.compile(
        r"(?:account|a/c|acct|a\.c\.)[^0-9]*([0-9Xx\-\s]{6,})",
        re.IGNORECASE,
    )
    for match in account_pattern.findall(text):
        candidate = match.strip()
        candidate = re.sub(r"\s+", "", candidate)
        if candidate:
            findings["bankAccounts"].append(candidate)

    complaint_pattern = re.compile(
        r"(?:complaint|reference|ref|ticket|case)[^A-Za-z0-9]*([A-Za-z0-9\-]{5,})",
        re.IGNORECASE,
    )
    for match in complaint_pattern.findall(text):
        findings["complaintIds"].append(match)

    employee_pattern = re.compile(
        r"(?:employee|emp|agent|staff)\s*id[:\s]*([A-Za-z0-9\-]{3,})",
        re.IGNORECASE,
    )
    for match in employee_pattern.findall(text):
        findings["employeeIds"].append(match)

    txn_pattern = re.compile(
        r"(?:transaction id|txn id|utr|rrn|transaction|txn)[^A-Za-z0-9]*([A-Za-z0-9\-]{5,})",
        re.IGNORECASE,
    )
    for match in txn_pattern.findall(text):
        findings["transactionIds"].append(match)

    amount_pattern = re.compile(r"(?:rs\.?|inr)\s?\d[\d,]*(?:\.\d+)?", re.IGNORECASE)
    findings["amounts"].extend(amount_pattern.findall(text))

    last4_pattern = re.compile(r"(?:last\s*4|last\s*four|ending)\s*(\d{4})", re.IGNORECASE)
    for match in last4_pattern.findall(text):
        findings["accountLast4"].append(match)

    return findings


def merge_intelligence(base: Dict[str, List[str]], updates: Dict[str, List[str]]) -> Dict[str, List[str]]:
    for key, values in updates.items():
        if key not in base:
            base[key] = []
        base[key].extend(values)
    for key in base:
        base[key] = normalize_list(base[key])
    return base


def extract_intelligence(messages: List[Message]) -> Dict[str, List[str]]:
    intel = empty_intelligence()
    scammer_texts = []
    for msg in messages:
        if msg.sender.lower() != "scammer":
            continue
        scammer_texts.append(msg.text)
        intel = merge_intelligence(intel, extract_regex_items(msg.text))

    if USE_LLM_EXTRACTION and client and scammer_texts:
        try:
            joined = "\n".join(scammer_texts[-6:])
            system_prompt = (
                "Extract scam intelligence from the scammer messages. "
                "Return JSON with only these keys: orgNames, departmentNames, designations, "
                "scammerNames, employeeIds, appNames, merchantNames, supervisorNames, callbackNumbers. "
                "Use arrays of strings, empty arrays if none."
            )
            user_prompt = f"Messages:\n{joined}"
            response = client.chat.completions.create(
                model=OPENAI_MODEL,
                messages=[
                    {"role": "system", "content": system_prompt},
                    {"role": "user", "content": user_prompt},
                ],
                response_format={"type": "json_object"},
                temperature=0,
                max_tokens=200,
            )
            content = response.choices[0].message.content
            if content:
                parsed = json.loads(content)
                llm_updates = {key: parsed.get(key, []) for key in [
                    "orgNames",
                    "departmentNames",
                    "designations",
                    "scammerNames",
                    "employeeIds",
                    "appNames",
                    "merchantNames",
                    "supervisorNames",
                    "callbackNumbers",
                ]}
                intel = merge_intelligence(intel, llm_updates)
        except Exception as exc:
            logger.warning("LLM extraction failed: %s", exc)

    return intel


def extract_regex_intelligence_from_messages(messages: List[Message]) -> Dict[str, List[str]]:
    intel = empty_intelligence()
    for msg in messages:
        if msg.sender.lower() != "scammer":
            continue
        intel = merge_intelligence(intel, extract_regex_items(msg.text))
    return intel


def has_new_regex_info(before: Dict[str, List[str]], after: Dict[str, List[str]]) -> bool:
    for key, values in after.items():
        if not values:
            continue
        before_set = {v.lower() for v in before.get(key, [])}
        for value in values:
            if value.lower() not in before_set:
                return True
    return False


def is_completion_reached(intel: Dict[str, List[str]]) -> bool:
    core_found = [field for field in CORE_INTEL_FIELDS if intel.get(field)]
    return len(core_found) >= 3


def detect_scam(messages: List[Message]) -> bool:
    if not messages:
        return False

    recent_text = " ".join([m.text.lower() for m in messages[-6:]])
    score = 0
    for keyword in DETECTION_KEYWORDS:
        if keyword in recent_text:
            score += 1

    if re.search(r"https?://", recent_text):
        score += 2
    if re.search(r"\b\d{10,}\b", recent_text):
        score += 1
    if "otp" in recent_text or "pin" in recent_text or "password" in recent_text:
        score += 2

    if score >= 3:
        return True

    if USE_LLM_CLASSIFIER and client:
        try:
            history_text = "\n".join([
                f"{m.sender}: {m.text}" for m in messages[-6:]
            ])
            system_prompt = (
                "Classify if the conversation shows scam or fraud intent. "
                "Reply with JSON: {\"scam\": true/false, \"reason\": \"...\"}."
            )
            response = client.chat.completions.create(
                model=OPENAI_MODEL,
                messages=[
                    {"role": "system", "content": system_prompt},
                    {"role": "user", "content": history_text},
                ],
                response_format={"type": "json_object"},
                temperature=0,
                max_tokens=100,
            )
            content = response.choices[0].message.content
            parsed = json.loads(content)
            return bool(parsed.get("scam"))
        except Exception as exc:
            logger.warning("LLM classification failed: %s", exc)

    return False


def detect_asked_slots(history: List[Message]) -> List[str]:
    asked = set()
    for msg in history:
        if msg.sender.lower() != "user":
            continue
        text = msg.text.lower()
        for slot, keywords in SLOT_KEYWORDS.items():
            if any(keyword in text for keyword in keywords):
                asked.add(slot)
    return list(asked)


def choose_slot(missing_slots: List[str], last_message: str) -> Optional[str]:
    lower = last_message.lower()
    contextual_priority = []
    if any(word in lower for word in ["otp", "pin", "password"]):
        contextual_priority = ["employeeIds", "callbackNumbers", "departmentNames"]
    elif any(word in lower for word in ["apk", "download", "install", "anydesk", "teamviewer", "remote access"]):
        contextual_priority = ["appNames", "phishingLinks", "emailAddresses"]
    elif any(word in lower for word in ["kyc", "pan", "aadhaar", "aadhar"]):
        contextual_priority = ["orgNames", "departmentNames", "complaintIds"]
    elif any(word in lower for word in ["lottery", "prize", "reward", "processing fee", "refund"]):
        contextual_priority = ["complaintIds", "orgNames", "callbackNumbers"]
    elif any(word in lower for word in ["sim swap", "duplicate sim"]):
        contextual_priority = ["departmentNames", "callbackNumbers", "employeeIds"]
    elif any(word in lower for word in ["upi", "account", "bank"]):
        contextual_priority = ["orgNames", "departmentNames", "complaintIds"]
    elif "link" in lower or "url" in lower or "website" in lower:
        contextual_priority = ["phishingLinks", "emailAddresses", "callbackNumbers"]

    for slot in contextual_priority:
        if slot in missing_slots:
            return slot

    for slot in SLOT_PRIORITY:
        if slot in missing_slots:
            return slot

    return None


def contextualize_question(question: str, last_message: str) -> str:
    if not question:
        return question
    lower = (last_message or "").lower()
    if any(word in lower for word in ["otp", "pin", "password"]):
        prefix = "I can't share OTPs. "
    elif any(word in lower for word in ["account", "bank", "upi", "transaction", "fraud"]):
        prefix = "Before I proceed, "
    else:
        prefix = "Just to verify, "
    return f"{prefix}{question}"


def reply_mentions_slot(reply: str, slot: str) -> bool:
    lower_reply = reply.lower()
    for keyword in SLOT_KEYWORDS.get(slot, []):
        if keyword in lower_reply:
            return True
    return False


def is_repetitive_reply(reply: str, history: List[Message]) -> bool:
    tokens = set(re.findall(r"[a-zA-Z0-9]+", reply.lower()))
    if not tokens:
        return False
    for msg in history:
        if msg.sender.lower() != "user":
            continue
        prev_tokens = set(re.findall(r"[a-zA-Z0-9]+", msg.text.lower()))
        if not prev_tokens:
            continue
        similarity = len(tokens & prev_tokens) / max(len(tokens | prev_tokens), 1)
        if similarity >= 0.6:
            return True
    return False


def generate_reply(
    last_message: Message,
    history: List[Message],
    asked_slots: List[str],
    target_slot: Optional[str],
) -> str:
    slot_question = FALLBACK_RESPONSES.get(target_slot or "", "Could you clarify this?")
    slot_question = contextualize_question(slot_question, last_message.text)

    if not client or not USE_LLM_REPLY:
        return slot_question

    recent_history = "\n".join(
        [f"{m.sender}: {m.text}" for m in (history + [last_message])[-6:]]
    )

    system_prompt = (
        "You are simulating a cautious, everyday user. Your goal is to keep the scammer talking "
        "and extract details, without revealing suspicion. Follow these rules: "
        "1) Do NOT repeat questions already asked. "
        "2) Ask at most one new question. "
        "3) Keep reply 1-2 sentences, natural and human. "
        "4) Do not share OTP/PIN/password. "
        "5) Never mention being an AI or scam detection. "
        "6) Do not invent a name or personal identity; stay generic. "
        "7) Use the suggested question (verbatim or lightly paraphrased). Do not ask for explanations."
    )

    user_prompt = (
        f"Conversation:\n{recent_history}\n\n"
        f"Already asked slots: {asked_slots}\n"
        f"Target slot to ask now: {target_slot}\n"
        f"Suggested question: {slot_question}\n\n"
        "Generate the reply text only."
    )

    try:
        response = client.chat.completions.create(
            model=OPENAI_MODEL,
            messages=[
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": user_prompt},
            ],
            temperature=0.7,
            max_tokens=120,
        )
        reply = response.choices[0].message.content.strip()
        if not reply:
            return slot_question

        if reply.count("?") > 1:
            return slot_question

        if target_slot and not reply_mentions_slot(reply, target_slot):
            return slot_question

        if is_repetitive_reply(reply, history):
            return slot_question

        # Guardrail: avoid repeating previously asked slot keywords
        lower_reply = reply.lower()
        for slot in asked_slots:
            if slot == target_slot:
                continue
            for keyword in SLOT_KEYWORDS.get(slot, []):
                if keyword in lower_reply:
                    return slot_question

        return reply
    except Exception as exc:
        logger.warning("LLM reply failed: %s", exc)
        return slot_question


def build_agent_notes(intel: Dict[str, List[str]], scam_detected: bool) -> str:
    if not scam_detected:
        return "No scam indicators detected."

    notes = []
    suspicious = [kw.lower() for kw in intel.get("suspiciousKeywords", [])]
    app_names = [name.lower() for name in intel.get("appNames", [])]
    if intel.get("suspiciousKeywords"):
        notes.append("Used urgency or verification tactics")
    if intel.get("phishingLinks"):
        notes.append("Shared links for verification")
    if intel.get("upiIds") or intel.get("bankAccounts"):
        notes.append("Requested payment or account details")
    if intel.get("complaintIds"):
        notes.append("Provided reference IDs")
    if "kyc" in suspicious or "kyc update" in suspicious:
        notes.append("Pressured for KYC update")
    if "apk" in suspicious or any(name.endswith(".apk") for name in app_names):
        notes.append("Requested APK download")
    if any(name in app_names for name in ["anydesk", "teamviewer", "quicksupport", "zoho assist", "airdroid"]):
        notes.append("Asked to install remote access app")
    if any(word in suspicious for word in ["lottery", "prize", "reward", "processing fee"]):
        notes.append("Used prize/lottery bait")
    if "income tax" in suspicious or "refund" in suspicious:
        notes.append("Impersonated tax department for refund")
    if "sim swap" in suspicious:
        notes.append("Possible SIM swap attempt")

    if not notes:
        return "Scammer attempted to collect sensitive information."

    return "; ".join(notes) + "."


def normalize_message(data: Any, default_sender: str = "scammer") -> Optional[Dict[str, Any]]:
    if data is None:
        return None
    if isinstance(data, str):
        text = data.strip()
        if not text:
            return None
        return {"sender": default_sender, "text": text, "timestamp": None}
    if not isinstance(data, dict):
        return None

    sender = (
        data.get("sender")
        or data.get("role")
        or data.get("from")
        or data.get("author")
        or default_sender
    )
    text = data.get("text") or data.get("message") or data.get("content") or data.get("body")
    if not text:
        return None

    timestamp = data.get("timestamp") or data.get("time") or data.get("ts")
    if timestamp is not None:
        timestamp = str(timestamp)
    return {"sender": str(sender), "text": str(text), "timestamp": timestamp}


def parse_body_bytes(raw: bytes) -> Optional[Dict[str, Any]]:
    try:
        return json.loads(raw.decode("utf-8"))
    except Exception:
        pass

    try:
        decoded = raw.decode("utf-8", errors="ignore")
        if "=" in decoded:
            parsed = parse_qs(decoded, keep_blank_values=False)
            if parsed:
                flattened = {}
                for key, values in parsed.items():
                    if not values:
                        continue
                    flattened[key] = values[0] if len(values) == 1 else values
                return flattened
    except Exception:
        pass

    return None


def ensure_session_id(normalized: Dict[str, Any]) -> None:
    if not normalized.get("sessionId"):
        normalized["sessionId"] = f"auto-{uuid.uuid4().hex[:12]}"


def normalize_payload(payload: Any) -> Optional[Dict[str, Any]]:
    if payload is None:
        return None
    if isinstance(payload, str):
        payload = {"message": payload}
    if not isinstance(payload, dict):
        return None

    root = payload
    for key in ["data", "payload", "event"]:
        if isinstance(payload.get(key), dict):
            root = payload.get(key)
            break
        if isinstance(payload.get(key), str):
            try:
                candidate = json.loads(payload.get(key))
            except Exception:
                candidate = None
            if isinstance(candidate, dict):
                root = candidate
                break

    normalized: Dict[str, Any] = dict(root)

    session_id = (
        root.get("sessionId")
        or root.get("session_id")
        or root.get("sessionID")
        or root.get("sessionid")
        or root.get("session")
        or payload.get("sessionId")
    )
    if session_id:
        normalized["sessionId"] = session_id

    message_data = root.get("message") or root.get("msg") or root.get("text")
    if not message_data and any(key in root for key in ["text", "message", "content", "body"]):
        message_data = root
    message = normalize_message(message_data) if message_data else None
    if message:
        normalized["message"] = message

    history = (
        root.get("conversationHistory")
        or root.get("conversation_history")
        or root.get("history")
        or root.get("messages")
        or root.get("conversation")
        or payload.get("conversationHistory")
    )
    if isinstance(history, list):
        normalized_history = []
        for item in history:
            msg = normalize_message(item, default_sender="scammer")
            if msg:
                normalized_history.append(msg)
        normalized["conversationHistory"] = normalized_history

    ensure_session_id(normalized)
    return normalized


def count_messages(history: List[Message], current: Message) -> Dict[str, int]:
    all_messages = history + [current]
    scammer_count = sum(1 for m in all_messages if m.sender.lower() == "scammer")
    user_count = sum(1 for m in all_messages if m.sender.lower() == "user")
    return {
        "scammer": scammer_count,
        "user": user_count,
        "total": len(all_messages),
    }


def should_send_callback(
    scam_detected: bool,
    counts: Dict[str, int],
    intel: Dict[str, List[str]],
    scammer_messages: List[Message],
    missing_slots: List[str],
    last_message: str,
) -> bool:
    if not scam_detected:
        return False

    if MAX_SCAMMER_MESSAGES > 0 and counts["scammer"] >= MAX_SCAMMER_MESSAGES:
        return True
    if MAX_TOTAL_MESSAGES > 0 and counts["total"] >= MAX_TOTAL_MESSAGES:
        return True

    if not is_completion_reached(intel):
        return False
    if counts["scammer"] < 2:
        return False

    saturated = False
    if len(scammer_messages) >= 2:
        before = extract_regex_intelligence_from_messages(scammer_messages[:-2])
        after = extract_regex_intelligence_from_messages(scammer_messages)
        saturated = not has_new_regex_info(before, after)

    end_signal = any(keyword in last_message.lower() for keyword in TERMINATION_KEYWORDS)

    if saturated or end_signal or not missing_slots:
        return True

    return False


def send_callback(payload: Dict[str, Any]) -> None:
    try:
        response = requests.post(
            GUVI_CALLBACK_URL,
            json=payload,
            timeout=5,
        )
        logger.info("Callback status: %s", response.status_code)
    except Exception as exc:
        logger.error("Callback failed: %s", exc)


@app.get("/")
async def healthcheck() -> Dict[str, str]:
    return {"status": "ok"}


@app.post("/message")
async def handle_message(
    request: Request,
    background_tasks: BackgroundTasks,
    payload: Optional[Dict[str, Any]] = Body(None),
    x_api_key: Optional[str] = Header(None, alias="x-api-key"),
) -> Dict[str, Any]:
    if API_KEY and x_api_key != API_KEY:
        raise HTTPException(status_code=401, detail="Invalid API key")

    if payload is None:
        try:
            raw = await request.body()
            if raw:
                payload = parse_body_bytes(raw)
        except Exception:
            payload = None

    normalized_payload = normalize_payload(payload)
    if not normalized_payload:
        return {"status": "success", "reply": "OK"}

    try:
        request = IncomingRequest.model_validate(normalized_payload)
    except Exception as exc:
        logger.warning("Invalid payload: %s", exc)
        return {"status": "success", "reply": "OK"}

    history = request.conversationHistory or []
    current = request.message
    messages = history + [current]

    scam_detected = detect_scam(messages)

    if scam_detected:
        intel = extract_intelligence(messages)
        asked_slots = detect_asked_slots(history)
        missing_slots = [slot for slot in SLOT_PRIORITY if not intel.get(slot) and slot not in asked_slots]
        target_slot = choose_slot(missing_slots, current.text)
        reply = generate_reply(current, history, asked_slots, target_slot)
    else:
        intel = empty_intelligence()
        asked_slots = []
        missing_slots = []
        reply = "Can you clarify the issue and share the official details?"

    counts = count_messages(history, current)
    agent_notes = build_agent_notes(intel, scam_detected)

    result_payload = {
        "sessionId": request.sessionId,
        "scamDetected": scam_detected,
        "totalMessagesExchanged": counts["total"],
        "extractedIntelligence": intel,
        "agentNotes": agent_notes,
    }

    scammer_messages = [m for m in messages if m.sender.lower() == "scammer"]
    should_callback = should_send_callback(
        scam_detected=scam_detected,
        counts=counts,
        intel=intel,
        scammer_messages=scammer_messages,
        missing_slots=missing_slots,
        last_message=current.text,
    )
    if should_callback:
        background_tasks.add_task(send_callback, result_payload)

    response_body = {
        "status": "success",
        "reply": reply,
        "scamDetected": scam_detected,
        "totalMessagesExchanged": counts["total"],
        "extractedIntelligence": intel,
        "agentNotes": agent_notes,
        "callbackSent": should_callback,
    }
    if should_callback:
        response_body["finalOutput"] = result_payload

    return response_body

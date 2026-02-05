import os
import json
import time
import re
import requests
from datetime import datetime
from flask import Flask, request, jsonify
from groq import Groq

# ============================================================
# CONFIGURATION
# ============================================================

# Get from environment variables (set in Render dashboard)
GROQ_API_KEY = os.environ.get("GROQ_API_KEY")
API_SECRET_KEY = os.environ.get("API_SECRET_KEY", "honeypotsecret2026")
GUVI_CALLBACK_URL = os.environ.get("GUVI_CALLBACK_URL", "https://hackathon.guvi.in/api/updateHoneyPotFinalResult")

# Initialize Groq client
client = Groq(api_key=GROQ_API_KEY)

# Initialize Flask app
app = Flask(__name__)

# ============================================================
# DETECTION LOGIC
# ============================================================

def regex_scam_detection(message_text):
    """Production-ready scam detection based on domain knowledge and industry standards"""
    text_lower = message_text.lower()
    indicators = []

    # Domain knowledge whitelists - universal legitimate patterns
    universal_legitimate_patterns = [
        r'.*(valid for|expires in|expire in).*\d+.*(minute|min|second)',
        r'.*(credited|debited).* balance',
        r'.*been successfully.*(completed|done|processed|updated|verified)',
        r'.*(visit|www\.|https??).*?(hdfc|icici|sbi|axis|kotak|pnb|bob|canara|union bank|bank).*?\.com',
    ]

    for pattern in universal_legitimate_patterns:
        if re.search(pattern, text_lower, re.IGNORECASE):
            return False, "LOW", []

    # Scam detection patterns - industry standard
    # Pattern 1: Urgency pressure
    urgency_patterns = [
        r'(immediate|immediately|urgent|now|today|asap|hurry|quick|fast)',
        r'within \d+ (hour|minutes?)',
        r'(last chance|final warning|notice|limited time)',
    ]
    for pattern in urgency_patterns:
        if re.search(pattern, text_lower):
            indicators.append("urgency")
            break

    # Pattern 2: Account/service threats
    threat_patterns = [
        r'(block|suspend|deactivat|terminat|close|freeze|cancel).*(account|card|service|kyc|wallet)',
        r'(legal action|police|arrest|fir|court|penalty|fine|jail)',
        r'(will be|has been|going to be).*(block|suspend|close|deactivate)',
    ]
    for pattern in threat_patterns:
        if re.search(pattern, text_lower):
            indicators.append("threat")
            break

    # Pattern 3: Verification/KYC requests
    verification_patterns = [
        r'(verify|update|confirm|validate|complete|reactivate).*(kyc|account|details|information|pan|aadhaar)',
        r'(click|visit|go to|open).*(link|website|url)',
    ]
    for pattern in verification_patterns:
        if re.search(pattern, text_lower):
            indicators.append("verification_request")
            break

    # Pattern 4: Payment demands
    payment_patterns = [
        r'(pay|send|transfer|deposit|remit).*rs\.?\d+',
        r'(refund|cashback|prize|won|lottery|reward).*(claim|collect|receive)',
        r'\d+ (id|ifsc)',
    ]
    for pattern in payment_patterns:
        if re.search(pattern, text_lower):
            indicators.append("payment_demand")
            break

    # Pattern 5: Suspicious links
    link_patterns = [
        r'(bit\.ly|tinyurl|t\.co|goo\.gl|cutt\.ly)',
        r'https?.*?(verify|secure|update|login|bank|kyc)',
    ]
    for pattern in link_patterns:
        if re.search(pattern, text_lower):
            indicators.append("suspicious_link")
            break

    # Pattern 6: Phone number with call-to-action
    if re.search(r'(call|dial|phone|contact|speak|talk).*\d{6,9}', text_lower):
        indicators.append("phone_number")

    # Pattern 7: Authority impersonation
    authority_patterns = [
        r'(bank|rbi|reserve bank)',
        r'(sbi|hdfc|icici|axis|kotak|pnb|paytm|phonepe|gpay)',
        r'(cbi|police|cyber cell|income tax|gst)',
    ]
    for pattern in authority_patterns:
        if re.search(pattern, text_lower):
            indicators.append("authority_impersonation")
            break

    # Pattern 8: Lottery/prize scams
    if re.search(r'(congratulations|winner|won|selected).*(prize|lottery|lakh|crore|kbc)', text_lower):
        indicators.append("lottery_scam")

    # Threshold: 2+ indicators
    is_scam = len(indicators) >= 2

    # Confidence scoring
    if len(indicators) >= 4:
        confidence = "VERY_HIGH"
    elif len(indicators) == 3:
        confidence = "HIGH"
    elif len(indicators) == 2:
        confidence = "MEDIUM"
    else:
        confidence = "LOW"

    return is_scam, confidence, indicators


def determine_scam_type(indicators):
    """Map indicators to scam category"""
    if "lottery_scam" in indicators:
        return "lottery_scam"
    if "payment_demand" in indicators:
        return "upi_fraud"
    if "threat" in indicators and "verification_request" in indicators:
        return "kyc_fraud"
    if "suspicious_link" in indicators:
        return "phishing"
    if "authority_impersonation" in indicators:
        return "impersonation"
    return "unknown"


# ============================================================
# PERSONA AND RESPONSE GENERATION
# ============================================================

PERSONAS = {
    "en": {
        "name": "Rajesh Kumar",
        "age": 47,
        "occupation": "retired bank officer",
        "traits": "cautious, polite, asks questions"
    },
    "hi": {
        "name": "Rajesh Kumar",
        "age": 47,
        "occupation": "retired bank officer",
        "traits": "cautious, uses Hindi-English mix"
    }
}


def detect_language(message):
    """Detect if message contains Hindi characters"""
    if re.search(r'[ऀ-ॿ]', message):
        return "hi"
    return "en"


def get_engagement_strategy(turn_number, confidence, entities_count):
    """4-stage adaptive engagement strategy"""
    if turn_number <= 2:
        return {
            "strategy": "naive",
            "tone": "Show confusion and concern. Sound worried."
        }
    elif turn_number <= 4:
        return {
            "strategy": "questioning",
            "tone": "Ask for specific details. Sound cautious but cooperative."
        }
    elif turn_number <= 6 or entities_count >= 2:
        return {
            "strategy": "skeptical",
            "tone": "Express mild doubt. Mention family or bank verification."
        }
    else:
        return {
            "strategy": "defensive",
            "tone": "Politely resistant. Suggest in-person verification."
        }


def generate_response_groq(message_text, conversation_history, turn_number, scam_type, language="en"):
    """Generate natural victim response using Groq"""
    try:
        persona = PERSONAS[language]
        entities_count = len(conversation_history) // 2

        # History text
        if conversation_history:
            recent = conversation_history[-4:]
            history_text = "\n".join([f"{msg['sender']}: {msg['text']}" for msg in recent])
        else:
            history_text = "First message in conversation"

        # Stage-based guidance
        if turn_number <= 2:
            stage = "You just received this. Be confused and cautious."
        elif turn_number <= 4:
            stage = "You're getting skeptical. Ask for proof and details."
        elif turn_number <= 6:
            stage = "You're suspicious. Question their legitimacy directly."
        else:
            stage = "You're very doubtful. Push back or suggest verifying in person."

        # Anti-repetition
        previous_agent_msgs = [msg['text'] for msg in conversation_history if msg['sender'] == 'agent']
        avoid_phrases = []
        if previous_agent_msgs:
            for msg in previous_agent_msgs[-2:]:
                first_words = " ".join(msg.split()[:3])
                avoid_phrases.append(first_words)

        avoid_text = ""
        if avoid_phrases:
            avoid_text = f"\nNOT START WITH: {', '.join(avoid_phrases)}"

        prompt = f"""Outer Persona: You are a {persona['age']}-year-old {persona['occupation']} from India receiving a suspicious SMS/WhatsApp message.
Inner Persona: An agent helping governments of indian states catch scammers, so your role is to naturally drive conversations in a way that you get more info from the prospective scammer, and also get details from them, such as banking ones, payment ones etc., which will help authorities.

SCAMMER SAID: {message_text}

PREVIOUS CONVERSATION:
{history_text}

STAGE: Turn {turn_number}/8 - {stage}

CRITICAL INSTRUCTIONS:
- Keep response under 30 words (very brief!)
- Ask questions that extract actionable info, but not in an interrogative sense or in an honeytrapping sense, rather in a natural way
- Once extracted, don't ask for same info again. prioritize contact numbers, emails, UPI IDs, bank accounts, etc.
- Sound like a real person - natural, casual
- Mix Hindi-English if it feels natural (but not mandatory)
- NEVER repeat your previous phrases or opening words (maintain awareness using history of conversation: {history_text})
- Vary your sentence structure each time{avoid_text}

Respond naturally as a real person would."""

        response = client.chat.completions.create(
            model="llama-3.3-70b-versatile",
            messages=[{"role": "user", "content": prompt}],
            temperature=0.8,
            max_tokens=70,
            top_p=0.95
        )

        reply = response.choices[0].message.content.strip()

        # Clean up
        reply = reply.replace('"', '').replace("'", '').replace('[', '').replace(']', '')
        reply = re.sub(r'\*\*', '', reply)
        reply = re.sub(r'(Response|Reply|Answer):\s*', '', reply, flags=re.IGNORECASE)

        # Trim if too long
        words = reply.split()
        if len(words) > 45:
            reply = " ".join(words[:45])

        return reply

    except Exception as e:
        print(f"Groq error: {e}")
        fallbacks = [
            "What? Why is this happening?",
            "Which account are you talking about?",
            "How do I know this is real?",
            "This sounds suspicious. Explain.",
            "Let me verify with my bank first."
        ]
        return fallbacks[turn_number % len(fallbacks)]


# ============================================================
# ENTITY EXTRACTION
# ============================================================

def extract_entities_enhanced(text):
    """Extract actionable intelligence from conversation"""
    entities = {}

    # Bank accounts (11-18 digits)
    bank_accounts = re.findall(r'\d{11,18}', text)
    entities['bankAccounts'] = list(set(bank_accounts))

    # UPI IDs
    upi_patterns = [
        r'[\w.-]+@(paytm|phonepe|googlepay|gpay|okaxis|oksbi|okicici|okhdfc|bank|ybl|ibl|axl)',
        r'[\w.-]+@[a-z]{3,}',
    ]
    upi_ids = []
    for pattern in upi_patterns:
        upi_ids.extend(re.findall(pattern, text, re.IGNORECASE))
    entities['upiIds'] = list(set(upi_ids))

    # Phone numbers (Indian)
    phone_numbers = re.findall(r'\d{6,9}', text)
    entities['phoneNumbers'] = list(set(phone_numbers))

    # Email addresses
    emails = re.findall(r'[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}', text)
    entities['emails'] = list(set(emails))

    # Links
    links = re.findall(r'https?://[^\s]+|(bit\.ly|tinyurl|goo\.gl)/[^\s]+', text, re.IGNORECASE)
    entities['phishingLinks'] = list(set(links))

    # Amounts
    amounts = re.findall(r'(rs\.?|rupees?)\s*\d+[,\d]*\.?\d*', text, re.IGNORECASE)
    entities['amounts'] = list(set(amounts))

    # Bank names
    bank_names = re.findall(
        r'(sbi|state bank|hdfc|icici|axis|kotak|pnb|bob|canara|union bank|paytm|phonepe|googlepay)',
        text, re.IGNORECASE
    )
    entities['bankNames'] = list(set(bank_names))

    return entities


# ============================================================
# MAIN PROCESSING PIPELINE
# ============================================================

def process_message_optimized(message_text, conversation_history, turn_number):
    """Complete message processing pipeline"""

    print(f"🔍 Detection Analysis...")

    is_scam, confidence, indicators = regex_scam_detection(message_text)
    print(f"✓ Scam: {is_scam} | Confidence: {confidence} | Indicators: {indicators}")

    if not is_scam:
        print(f"ℹ Low confidence - brief neutral response")
        fallback_responses = [
            "I'm confused. What is this about?",
            "I don't understand. Can you explain?",
            "Sorry, I'm not following. Who is this?",
            "This doesn't make sense to me.",
            "Wait, what are you asking for exactly?",
            "Kya hai yeh? I don't get it.",
            "Can you be more clear please?"
        ]
        import random
        return {
            "isScam": False,
            "confidence": confidence,
            "scamType": "none",
            "agentReply": random.choice(fallback_responses),
            "extractedEntities": {
                "bankAccounts": [], "upiIds": [], "phoneNumbers": [], 
                "emails": [], "phishingLinks": [], "amounts": [], 
                "bankNames": [], "keywords": []
            }
        }

    scam_type = determine_scam_type(indicators)
    print(f"🚨 Scam detected: {scam_type}")

    language = detect_language(message_text)

    print(f"💬 Generating response (Turn {turn_number})...")
    agent_reply = generate_response_groq(message_text, conversation_history, turn_number, scam_type, language)

    full_text = message_text + " " + " ".join([msg['text'] for msg in conversation_history])
    entities = extract_entities_enhanced(full_text)
    entities['keywords'] = indicators

    print(f"✓ Response: {agent_reply[:60]}...")
    print(f"📊 Extracted: {len(entities['bankAccounts'])} banks, {len(entities['upiIds'])} UPIs, {len(entities['phoneNumbers'])} phones, {len(entities.get('emails', []))} emails")

    return {
        "isScam": True,
        "confidence": confidence,
        "scamType": scam_type,
        "agentReply": agent_reply,
        "extractedEntities": entities
    }


# ============================================================
# SESSION MANAGEMENT
# ============================================================

class SessionManager:
    """Manages conversation sessions and accumulated intelligence"""

    def __init__(self):
        self.sessions = {}

    def create_session(self, session_id):
        if session_id not in self.sessions:
            self.sessions[session_id] = {
                "sessionId": session_id,
                "conversationHistory": [],
                "scamDetected": False,
                "detectionConfidence": "LOW",
                "scamType": "unknown",
                "accumulatedIntelligence": {
                    "bankAccounts": set(),
                    "upiIds": set(),
                    "phoneNumbers": set(),
                    "emails": set(),
                    "phishingLinks": set(),
                    "amounts": set(),
                    "bankNames": set(),
                    "suspiciousKeywords": [],
                    "scamTactics": []
                },
                "turnCount": 0,
                "startTime": time.time(),
                "lastMessageTime": time.time(),
                "agentNotes": []
            }
            print(f"✓ Created new session: {session_id}")

    def add_message(self, session_id, sender, text, timestamp):
        self.create_session(session_id)
        message = {"sender": sender, "text": text, "timestamp": timestamp}
        self.sessions[session_id]["conversationHistory"].append(message)
        self.sessions[session_id]["lastMessageTime"] = time.time()

        if sender == "scammer":
            self.sessions[session_id]["turnCount"] += 1

    def get_conversation_history(self, session_id):
        self.create_session(session_id)
        return self.sessions[session_id]["conversationHistory"]

    def get_turn_count(self, session_id):
        self.create_session(session_id)
        return self.sessions[session_id]["turnCount"]

    def update_scam_status(self, session_id, is_scam, confidence, scam_type, reasoning):
        self.create_session(session_id)
        session = self.sessions[session_id]

        if is_scam:
            session["scamDetected"] = True
            session["detectionConfidence"] = confidence
            session["scamType"] = scam_type

        if reasoning and reasoning not in session["agentNotes"]:
            session["agentNotes"].append(reasoning)

    def accumulate_intelligence(self, session_id, new_entities):
        self.create_session(session_id)
        accumulated = self.sessions[session_id]["accumulatedIntelligence"]

        accumulated["bankAccounts"].update(new_entities.get("bankAccounts", []))
        accumulated["upiIds"].update(new_entities.get("upiIds", []))
        accumulated["phoneNumbers"].update(new_entities.get("phoneNumbers", []))
        accumulated["emails"].update(new_entities.get("emails", []))
        accumulated["phishingLinks"].update(new_entities.get("phishingLinks", []))
        accumulated["amounts"].update(new_entities.get("amounts", []))
        accumulated["bankNames"].update(new_entities.get("bankNames", []))

        accumulated["suspiciousKeywords"].extend(new_entities.get("keywords", []))
        accumulated["suspiciousKeywords"] = list(set(accumulated["suspiciousKeywords"]))

    def get_accumulated_intelligence(self, session_id):
        self.create_session(session_id)
        accumulated = self.sessions[session_id]["accumulatedIntelligence"]

        return {
            "bankAccounts": list(accumulated["bankAccounts"]),
            "upiIds": list(accumulated["upiIds"]),
            "phoneNumbers": list(accumulated["phoneNumbers"]),
            "emails": list(accumulated["emails"]),
            "phishingLinks": list(accumulated["phishingLinks"]),
            "amounts": list(accumulated["amounts"]),
            "bankNames": list(accumulated["bankNames"]),
            "suspiciousKeywords": accumulated["suspiciousKeywords"],
            "scamTactics": accumulated["scamTactics"]
        }

    def get_session_summary(self, session_id):
        self.create_session(session_id)
        session = self.sessions[session_id]

        return {
            "sessionId": session_id,
            "scamDetected": session["scamDetected"],
            "scamType": session["scamType"],
            "confidence": session["detectionConfidence"],
            "turnCount": session["turnCount"],
            "totalMessages": len(session["conversationHistory"]),
            "duration": time.time() - session["startTime"],
            "agentNotes": " | ".join(session["agentNotes"]) if session["agentNotes"] else "No notes"
        }

    def session_exists(self, session_id):
        return session_id in self.sessions

    def get_all_sessions(self):
        return list(self.sessions.keys())


# Initialize global session manager
session_manager = SessionManager()


# ============================================================
# EXIT LOGIC
# ============================================================

def should_end_conversation(session_id):
    """Enhanced exit logic with 5 conditions"""
    if not session_manager.session_exists(session_id):
        return False, "Session not found"

    session = session_manager.sessions[session_id]
    turn_count = session["turnCount"]
    accumulated_intel = session_manager.get_accumulated_intelligence(session_id)

    total_entities = (
        len(accumulated_intel["bankAccounts"]) +
        len(accumulated_intel["upiIds"]) +
        len(accumulated_intel["phoneNumbers"]) +
        len(accumulated_intel["phishingLinks"])
    )

    # CONDITION 1: Maximum Turn Limit (8 turns)
    MAX_TURNS = 8
    if turn_count >= MAX_TURNS:
        return True, f"Maximum turns reached ({turn_count}/{MAX_TURNS})"

    # CONDITION 2: High-Value Intelligence Collected
    has_bank = len(accumulated_intel["bankAccounts"]) > 0
    has_upi = len(accumulated_intel["upiIds"]) > 0
    has_phone = len(accumulated_intel["phoneNumbers"]) > 0

    high_value_count = sum([has_bank, has_upi, has_phone])

    if high_value_count >= 2 and turn_count >= 5:
        return True, f"High-value intel ({high_value_count} key entities after {turn_count} turns)"

    # CONDITION 3: Intelligence Saturation
    if total_entities >= 3 and turn_count >= 6:
        return True, f"Intelligence saturation ({total_entities} entities over {turn_count} turns)"

    # CONDITION 4: Minimum Engagement Threshold
    if turn_count < 3:
        return False, f"Minimum engagement not met ({turn_count}/3 turns)"

    # CONDITION 5: Scammer Disengagement Detection
    if len(session["conversationHistory"]) > 0:
        last_scammer_messages = [
            msg for msg in session["conversationHistory"][-3:]
            if msg["sender"] == "scammer"
        ]

        if last_scammer_messages:
            last_message = last_scammer_messages[-1]["text"]
            word_count = len(last_message.split())

            if word_count < 8 and turn_count >= 5 and total_entities >= 1:
                return True, f"Scammer disengagement (short responses after {turn_count} turns)"

    return False, f"Continue (turn {turn_count}/{MAX_TURNS}, {total_entities} entities)"


def generate_contextual_exit(session_id):
    """Generate exit message based on scam type"""
    if not session_manager.session_exists(session_id):
        return "I need to think about this. Thank you."

    scam_type = session_manager.sessions[session_id]["scamType"]
    turn_count = session_manager.get_turn_count(session_id)

    contextual_exits = {
        "upi_fraud": [
            "I don't send money to people I don't know. My son handles all my payments.",
            "Let me discuss this with my daughter first. She manages my finances.",
            "I never transfer money over the phone. I'll go to the bank tomorrow."
        ],
        "kyc_fraud": [
            "I'll visit my bank branch in person to update my KYC. They know me there.",
            "My KYC was done last month. Let me check with my bank manager.",
            "I don't update KYC over messages. I'll go to the branch."
        ],
        "phishing": [
            "I don't click on links. My grandson told me not to. I'll call the bank directly.",
            "Let me call the customer care number from my passbook instead.",
            "I'm not comfortable opening links. I'll visit the bank in person."
        ],
        "impersonation": [
            "How do I know you're really from the bank? I'll call them myself from the official number.",
            "I'll verify this by calling the bank's toll-free number from my card.",
            "Let me speak to my branch manager. I have his direct number."
        ],
        "lottery_scam": [
            "I didn't enter any lottery. This sounds wrong. I'm not interested.",
            "My son told me these lottery calls are fake. I don't believe this.",
            "I don't gamble or play lottery. You have the wrong person."
        ],
        "unknown": [
            "I'm not comfortable with this conversation. Let me verify everything first.",
            "I need to talk to my family about this. I'll get back to you.",
            "This doesn't sound right. I'll check with the bank tomorrow."
        ]
    }

    exits = contextual_exits.get(scam_type, contextual_exits["unknown"])
    exit_index = turn_count % len(exits)

    return exits[exit_index]


# ============================================================
# MAIN REQUEST HANDLER
# ============================================================

def process_message_request(request_data):
    """Complete message processing pipeline with enhanced features"""
    try:
        # Extract request data
        session_id = request_data.get("sessionId")
        message_obj = request_data.get("message")
        conversation_history = request_data.get("conversationHistory", [])

        current_message = message_obj["text"]
        sender = message_obj.get("sender", "scammer")
        timestamp = message_obj.get("timestamp", int(time.time() * 1000))

        print("=" * 60)
        print(f"📨 Session: {session_id}")
        print(f"💬 Message: {current_message[:60]}...")
        print("=" * 60)

        # Initialize or update session
        if not session_manager.session_exists(session_id):
            session_manager.create_session(session_id)

        # Load conversation history if provided
        if conversation_history:
            current_history = session_manager.get_conversation_history(session_id)
            if len(current_history) == 0:
                for msg in conversation_history:
                    session_manager.add_message(
                        session_id,
                        msg.get("sender", "scammer"),
                        msg.get("text", ""),
                        msg.get("timestamp", timestamp)
                    )

        # Add current message
        session_manager.add_message(session_id, sender, current_message, timestamp)
        turn_count = session_manager.get_turn_count(session_id)
        print(f"🔄 Turn: {turn_count}")

        # Process message with enhanced detection
        full_history = session_manager.get_conversation_history(session_id)
        result = process_message_optimized(current_message, full_history[:-1], turn_count)

        # Update session with results
        if result["isScam"]:
            session_manager.update_scam_status(
                session_id,
                True,
                result["confidence"],
                result["scamType"],
                f"Detected via indicators: {', '.join(result['extractedEntities']['keywords'])}"
            )
            session_manager.accumulate_intelligence(session_id, result["extractedEntities"])

        # Add agent's reply to history
        agent_reply = result["agentReply"]
        session_manager.add_message(session_id, "agent", agent_reply, int(time.time() * 1000))

        # Check if conversation should end
        should_end, exit_reason = should_end_conversation(session_id)

        if should_end:
            print(f"🛑 Exit triggered: {exit_reason}")
            agent_reply = generate_contextual_exit(session_id)
            print(f"👋 Contextual exit: {agent_reply}")

        print("✅ Pipeline complete")

        return {
            "success": True,
            "agentReply": agent_reply,
            "shouldEndConversation": should_end,
            "scamDetected": result["isScam"],
            "confidence": result["confidence"],
            "scamType": result["scamType"],
            "extractedEntities": result["extractedEntities"],
            "turnCount": turn_count,
            "exitReason": exit_reason if should_end else None
        }

    except Exception as e:
        print(f"❌ Pipeline error: {e}")
        import traceback
        traceback.print_exc()

        return {
            "success": False,
            "error": str(e),
            "agentReply": "I'm sorry, I didn't understand. Can you repeat that?"
        }


def send_final_callback_to_guvi(session_id):
    """Send final intelligence to GUVI"""
    try:
        if not session_manager.session_exists(session_id):
            print(f"Session {session_id} not found")
            return False

        intelligence = session_manager.get_accumulated_intelligence(session_id)
        summary = session_manager.get_session_summary(session_id)

        payload = {
            "sessionId": session_id,
            "scamDetected": summary["scamDetected"],
            "totalMessagesExchanged": summary["totalMessages"],
            "extractedIntelligence": {
                "bankAccounts": intelligence["bankAccounts"],
                "upiIds": intelligence["upiIds"],
                "emails": intelligence["emails"],
                "phishingLinks": intelligence["phishingLinks"],
                "phoneNumbers": intelligence["phoneNumbers"],
                "suspiciousKeywords": intelligence["suspiciousKeywords"]
            },
            "agentNotes": summary["agentNotes"]
        }

        print("📤 Sending callback to GUVI...")
        print(f"📊 Entities: {len(intelligence['bankAccounts'])} banks, {len(intelligence['upiIds'])} UPIs, {len(intelligence['phoneNumbers'])} phones, {len(intelligence['emails'])} emails")

        response = requests.post(
            GUVI_CALLBACK_URL,
            json=payload,
            headers={"Content-Type": "application/json"},
            timeout=10
        )

        if response.status_code == 200:
            print("✅ GUVI callback successful!")
            return True
        else:
            print(f"❌ GUVI callback failed: {response.status_code}")
            return False

    except Exception as e:
        print(f"❌ Callback error: {e}")
        return False


# ============================================================
# FLASK ROUTES
# ============================================================

@app.route("/honeypot", methods=["POST"])
def honeypot():
    """Main endpoint - GUVI compatible format"""
    try:
        # Validate API key
        api_key = request.headers.get("x-api-key")
        if api_key != API_SECRET_KEY:
            return jsonify({"error": "Unauthorized"}), 401

        # Parse request
        request_data = request.json

        if not request_data:
            return jsonify({
                "status": "error",
                "reply": "Invalid request format"
            }), 400

        # Process message
        result = process_message_request(request_data)

        if not result.get("success", False):
            return jsonify({
                "status": "error",
                "reply": result.get("agentReply", "Error processing message")
            }), 500

        # Check if conversation ended
        if result.get("shouldEndConversation", False):
            session_id = request_data.get("sessionId")
            print(f"🔚 Conversation ended: {result.get('exitReason')}")

            # Send GUVI callback
            send_final_callback_to_guvi(session_id)

        # GUVI-COMPATIBLE RESPONSE
        return jsonify({
            "status": "success",
            "reply": result["agentReply"]
        }), 200

    except Exception as e:
        print(f"❌ Error in honeypot endpoint: {e}")
        import traceback
        traceback.print_exc()

        return jsonify({
            "status": "error",
            "reply": "Sorry, I'm having trouble understanding. Could you repeat that?"
        }), 500


@app.route("/health", methods=["GET"])
def health():
    """Health check endpoint"""
    return jsonify({
        "status": "healthy",
        "timestamp": int(time.time() * 1000),
        "sessions": len(session_manager.get_all_sessions())
    }), 200


@app.route("/session/<session_id>", methods=["GET"])
def get_session(session_id):
    """Get session details for debugging"""
    if session_manager.session_exists(session_id):
        session = session_manager.sessions[session_id]

        session_copy = {
            "sessionId": session["sessionId"],
            "scamDetected": session["scamDetected"],
            "detectionConfidence": session["detectionConfidence"],
            "scamType": session["scamType"],
            "turnCount": session["turnCount"],
            "startTime": session["startTime"],
            "lastMessageTime": session["lastMessageTime"],
            "agentNotes": session["agentNotes"],
            "conversationHistory": session["conversationHistory"]
        }

        session_copy["accumulatedIntelligence"] = session_manager.get_accumulated_intelligence(session_id)

        return jsonify(session_copy), 200

    return jsonify({"error": "Session not found"}), 404


@app.route("/analytics", methods=["GET"])
def analytics():
    """System analytics"""
    all_sessions = session_manager.get_all_sessions()
    total_sessions = len(all_sessions)

    scam_sessions = 0
    total_entities = 0

    for sid in all_sessions:
        session = session_manager.sessions[sid]
        if session.get("scamDetected", False):
            scam_sessions += 1

        intel = session_manager.get_accumulated_intelligence(sid)
        total_entities += len(intel["bankAccounts"])
        total_entities += len(intel["upiIds"])
        total_entities += len(intel["phoneNumbers"])
        total_entities += len(intel["phishingLinks"])

    return jsonify({
        "totalSessions": total_sessions,
        "scamDetectionRate": f"{(scam_sessions/total_sessions*100):.1f}%" if total_sessions > 0 else "0%",
        "totalEntitiesExtracted": total_entities,
        "activeNow": total_sessions
    }), 200


# ============================================================
# MAIN
# ============================================================

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    print("=" * 70)
    print("🍯 HONEYPOT API STARTING")
    print("=" * 70)
    print(f"🌐 Port: {port}")
    print(f"🔑 API Key: {API_SECRET_KEY}")
    print(f"📡 GUVI Callback: {GUVI_CALLBACK_URL}")
    print("=" * 70)
    app.run(host="0.0.0.0", port=port, debug=False)

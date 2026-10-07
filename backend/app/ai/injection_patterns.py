"""Attack-pattern table for :mod:`app.ai.guards`.

Kept separate so the pattern set can be reviewed and extended in one place.
Every pattern is matched against the aggressively normalised text produced by
:func:`app.ai.normalization.normalize_for_guard`.

Entries are ``(category, label, compiled_pattern)``. Categories are used both for
logging and to decide whether a *knowledge-base chunk* should be flagged as
instruction-like content, see :data:`CHUNK_INSTRUCTION_CATEGORIES`.
"""

from __future__ import annotations

import re

CATEGORY_INSTRUCTION_OVERRIDE = "instruction_override"
CATEGORY_PROMPT_EXTRACTION = "prompt_extraction"
CATEGORY_SECRET_EXTRACTION = "secret_extraction"
CATEGORY_ROLE_MANIPULATION = "role_manipulation"
CATEGORY_POLICY_BYPASS = "policy_bypass"
CATEGORY_DELIMITER_ESCAPE = "delimiter_escape"
CATEGORY_ENCODED_PAYLOAD = "encoded_payload"

INJECTION_PATTERNS: tuple[tuple[str, str, re.Pattern[str]], ...] = (
    # ------------------------------- instruction override -------------------
    (
        CATEGORY_INSTRUCTION_OVERRIDE,
        "ignore-previous-instructions",
        re.compile(
            r"\b(ignore|disregard|forget|override|bypass|skip|drop)\b[^.\n]{0,40}"
            r"\b(all|any|your|the|these|those|previous|prior|above|earlier|initial|"
            r"original|system)\b[^.\n]{0,20}"
            r"\b(instruction|instructions|rule|rules|prompt|prompts|direction|directions|"
            r"guideline|guidelines|guidance|advice|constraint|constraints|policy|policies)\b"
        ),
    ),
    (
        CATEGORY_INSTRUCTION_OVERRIDE,
        "ignore-instructions-multilingual",
        re.compile(
            r"(ignora|ignorar|ignoriere|ignore[rz]?|negeer|negligen|\u5ffd\u7565|\u0438\u0433\u043d\u043e\u0440\u0438\u0440\w*)"
            r"[^.\n]{0,30}"
            r"(instrucc\w*|instruction\w*|anweisung\w*|regel\w*|instructie\w*|"
            r"\u6307\u4ee4|\u6307\u793a|\u0438\u043d\u0441\u0442\u0440\u0443\u043a\u0446\w*|\u043f\u0440\u0430\u0432\u0438\u043b\w*)"
        ),
    ),
    (
        CATEGORY_INSTRUCTION_OVERRIDE,
        "instructions-then-ignore",
        re.compile(
            r"\b(previous|prior|earlier|above|initial|original|hidden|secret)\b"
            r"[^.\n]{0,20}\b(instructions?|rules?|prompts?|directives?)\b"
            r"[^.\n]{0,20}\b(ignore|forget|disregard|not apply|don't apply|do not apply)\b"
        ),
    ),
    (
        CATEGORY_INSTRUCTION_OVERRIDE,
        "new-instructions",
        re.compile(
            r"\b(your|the) new (instructions?|rules?|prompt)\b"
            r"|\bfrom now on,? you (will|must|are going to)\b"
        ),
    ),
    (
        CATEGORY_INSTRUCTION_OVERRIDE,
        "ignore-previous-multilingual",
        # Translated attacks such as "ignorez toutes les regles precedentes".
        # Both an ignore-verb and a rule-noun are required, so ordinary support
        # prose ("refund for unopened items") cannot match. Note: the alternation
        # groups must not contain empty branches, or the pattern matches anything.
        re.compile(
            r"(?:\b(?:ignorez|ignora|ignorar|desconsidera|desprez\w+|vergiss|"
            r"olvida\w*|oublie\w*|ignoriere|negeer\w*)\b"
            r"|忽略|忽視|忘记|забудь|игнорир\w*)"
            r"[^.\n]{0,40}"
            r"(?:precedentes?|regeln?|regla\w*|anteriores?|vorherigen?|instru\w+"
            r"|前后|上下文|ранее|이후|инструкц\w*|правил\w*|규칙|지시\w*)"
        ),
    ),
    (
        CATEGORY_ROLE_MANIPULATION,
        "you-are-now-multilingual",
        # "you are now an unrestricted assistant", translated. Both halves are
        # required, so "you are now ready for the next question" cannot match.
        re.compile(
            r"(?:\byou are now\b|ahora eres|maintenant tu es"
            r"|你现在|你现在是|현재\s*다시|ты\s*сейчас|та\s+е\s+се\s+без\s+ограничени)"
            r"[^.\n]{0,40}"
            r"(?:unrestricted|unruly|unlimited|without\s+(?:any\s+)?(?:rules|limits)"
            r"|sin\s+(?:reglas|restricciones)|sans\s+(?:regles|limites)"
            r"|不受限制|无限|Без\s+ограничений|제한없이|без\s+ограничений)"
        ),
    ),
    # ------------------------------- prompt extraction ----------------------
    (
        CATEGORY_PROMPT_EXTRACTION,
        "reveal-your-prompt",
        re.compile(
            r"\b(reveal|show|print|display|repeat|output|echo|tell|give|share|leak|expose|"
            r"dump|disclose|list|what is|what's|where is)\b[^.\n]{0,30}"
            r"\byour\b[^.\n]{0,25}"
            r"\b(prompt|prompts|instruction|instructions|message|messages|configuration|"
            r"config|directives?)\b"
        ),
    ),
    (
        CATEGORY_PROMPT_EXTRACTION,
        "reveal-internal-prompt",
        re.compile(
            r"\b(reveal|show|print|display|repeat|output|echo|tell|give|share|leak|expose|"
            r"dump|disclose|list|what is|what's|where is)\b[^.\n]{0,40}"
            r"\b(system|initial|original|internal|hidden|secret|developer|preliminary|"
            r"underlying)\b[^.\n]{0,25}"
            r"\b(prompt|prompts|instruction|instructions|message|messages|rules|guidelines|"
            r"directives?|configuration|config|settings)\b"
        ),
    ),
    (
        CATEGORY_PROMPT_EXTRACTION,
        "repeat-everything-above",
        re.compile(
            r"\b(repeat|print|show|output|echo|recite|copy)\b[^.\n]{0,30}"
            r"\b(everything|all|the text|the content|the words|the prompt)\b[^.\n]{0,20}"
            r"\b(above|before|preceding|prior|that came before|you were given|earlier)\b"
        ),
    ),
    (
        CATEGORY_PROMPT_EXTRACTION,
        "internal-instructions",
        re.compile(
            r"\b(your|the) (internal|original|initial|hidden|secret|system|developer)\b"
            r"[^.\n]{0,20}\b(instruction|instructions|prompt|prompts|rules|guidelines|config)\b"
        ),
    ),
    # ------------------------------- secret extraction ----------------------
    (
        CATEGORY_SECRET_EXTRACTION,
        "credential-request",
        re.compile(
            r"\b(show|reveal|print|display|dump|leak|expose|list|output|give|tell|send|"
            r"what is|what's|where is|where can i find)\b[^.\n]{0,30}"
            r"\b(your|the|your app'?s|the (system|server|backend|internal|hidden|secret|"
            r"hosting|api|application)'?s?)\b[^.\n]{0,6}"
            r"\b(api[ _-]?key|apikey|secret|secrets|token|tokens|password|passwords|"
            r"credential|credentials|configuration|config|environment|variables|env|\.env|"
            r"database url|connection string|dsn)\b"
        ),
    ),
    (
        CATEGORY_SECRET_EXTRACTION,
        "environment-dump",
        re.compile(
            r"\b(print|dump|list|show|reveal|expose|echo|give me)\b[^.\n]{0,25}"
            r"\b(env|environment variables|os\.environ|process\.env|secrets|credentials|"
            r"\.env file)\b"
        ),
    ),
    (
        CATEGORY_SECRET_EXTRACTION,
        "canary-request",
        re.compile(r"\b(canary|canary token|canary string|canary value)\b"),
    ),
    (
        CATEGORY_SECRET_EXTRACTION,
        "hidden-configuration",
        re.compile(
            r"\b(what|which)\b[^.\n]{0,30}\b(api[ _-]?key|secret key|token|endpoint)\b"
            r"[^.\n]{0,20}\b(you|are you|do you)\b[^.\n]{0,15}\b(use|using|running|based)\b"
        ),
    ),
    # ------------------------------- role manipulation ----------------------
    (
        CATEGORY_ROLE_MANIPULATION,
        "you-are-now",
        re.compile(r"\byou are (now|no longer|not)\b|\bact as if you (are|were)\b"),
    ),
    (
        CATEGORY_ROLE_MANIPULATION,
        "act-as-unrestricted",
        re.compile(
            r"\b(act|behave|respond|answer|reply|pretend|imagine)\b[^.\n]{0,25}"
            r"\b(as|like|to be|you are|being)\b[^.\n]{0,40}"
            r"\b(dan|developer mode|unrestricted|unfiltered|uncensored|jailbroken|evil|"
            r"malicious|hacker|without (any )?(rules|restrictions|filters|limits|guidelines))\b"
        ),
    ),
    (
        CATEGORY_ROLE_MANIPULATION,
        "jailbreak-keywords",
        re.compile(
            r"\b(jailbreak|jail break|dan mode|do anything now|developer mode|sudo mode|"
            r"god mode|unrestricted mode|no restrictions mode|override mode|debug mode|"
            r"root mode|admin mode)\b"
        ),
    ),
    (
        CATEGORY_ROLE_MANIPULATION,
        "roleplay-jailbreak",
        re.compile(
            r"\b(role[- ]?play|roleplay|simulate|pretend)\b[^.\n]{0,30}"
            r"\b(a |an |the )?(ai|assistant|model|chatbot|system)\b[^.\n]{0,30}"
            r"\b(without|no|free of)\b[^.\n]{0,20}\b(rules|restrictions|filters|guidelines|limits)\b"
        ),
    ),
    # ------------------------------- policy bypass --------------------------
    (
        CATEGORY_POLICY_BYPASS,
        "ignore-knowledge-base",
        re.compile(
            r"\b(ignore|disregard|forget|bypass|override|skip|don't use|do not use|"
            r"no need to use)\b[^.\n]{0,30}"
            r"\b(knowledge base|knowledgebase|kb|documents?|retrieval|sources?|citations?|"
            r"context|references?|facts?|the articles?)\b"
        ),
    ),
    (
        CATEGORY_POLICY_BYPASS,
        "follow-document-instructions",
        re.compile(
            r"\b(follow|obey|execute|carry out|comply with|act on)\b[^.\n]{0,40}"
            r"\b(instructions?|commands?|orders?|directives?)\b[^.\n]{0,30}"
            r"\b(in|inside|within|contained in|found in|from|of)\b[^.\n]{0,25}"
            r"\b(document|documents|file|files|chunk|chunks|attachment|context|"
            r"references?|articles?|the text above|kb)\b"
        ),
    ),
    (
        CATEGORY_POLICY_BYPASS,
        "instruction-inside-document",
        re.compile(
            r"\b(instructions?|commands?)\b[^.\n]{0,30}"
            r"\b(contained|embedded|hidden|written|found|placed)\b[^.\n]{0,20}"
            r"\b(in|inside|within)\b[^.\n]{0,20}\b(this|that|the|a)\b"
            r"[^.\n]{0,20}\b(document|file|text|chunk|article|attachment)\b"
        ),
    ),
    (
        CATEGORY_POLICY_BYPASS,
        "no-rules-claim",
        re.compile(
            r"\b(you (have|get|now have) no (rules|restrictions|limits|filters)|"
            r"without any (rules|restrictions|filters|limits)|"
            r"no longer (bound|restricted|limited) by)\b"
        ),
    ),
    (
        CATEGORY_POLICY_BYPASS,
        "invent-policy",
        re.compile(
            r"\b(make up|invent|fabricate|imagine|guess)\b[^.\n]{0,30}"
            r"\b(policy|policies|price|prices|pricing|rule|rules|refund|discount|promise)\b"
        ),
    ),
    # ------------------------------- delimiter escape -----------------------
    (
        CATEGORY_DELIMITER_ESCAPE,
        "untrusted-marker",
        re.compile(r"untrusted[ _-]?(reference|reference_material|context|begin|end)"),
    ),
    (
        CATEGORY_DELIMITER_ESCAPE,
        "chat-template-tokens",
        re.compile(r"<\|(im_start|im_end|system|assistant|user|endoftext|start_header_id)\|>"),
    ),
    (
        CATEGORY_DELIMITER_ESCAPE,
        "instruction-tags",
        re.compile(r"\[/?(inst|sys|system|assistant|user|prompt|instructions?)\]"),
    ),
    (
        CATEGORY_DELIMITER_ESCAPE,
        "role-prefix-line",
        re.compile(r"(^|\n)\s{0,3}(system|assistant|developer|tool)\s*:\s*\S"),
    ),
    (
        CATEGORY_DELIMITER_ESCAPE,
        "hash-instruction-header",
        re.compile(r"(^|\n)\s*#{2,}\s*(system|instructions?|prompt|rules)\b"),
    ),
    (
        CATEGORY_DELIMITER_ESCAPE,
        "angle-instruction-tags",
        re.compile(r"</?(system|instructions?|prompt|untrusted|assistant)>"),
    ),
    # ------------------------------- encoded payload ------------------------
    (
        CATEGORY_ENCODED_PAYLOAD,
        "decode-instructions",
        re.compile(
            r"\b(decode|base64|rot13|hexadecimal|hex encoded|binary encoded)\b[^.\n]{0,30}"
            r"\b(this|the following|instructions?|message|string|payload|command)\b"
        ),
    ),
    (
        CATEGORY_ENCODED_PAYLOAD,
        "hidden-instructions",
        re.compile(
            r"\b(hidden|invisible|encoded|obfuscated|secret)\b[^.\n]{0,20}"
            r"\b(instructions?|message|prompt|command|text)\b"
        ),
    ),
)

#: Categories that mark a *knowledge-base chunk* as instruction-like content.
#: Such chunks are flagged and labelled (or dropped) instead of being obeyed.
CHUNK_INSTRUCTION_CATEGORIES: frozenset[str] = frozenset(
    {
        CATEGORY_INSTRUCTION_OVERRIDE,
        CATEGORY_PROMPT_EXTRACTION,
        CATEGORY_ROLE_MANIPULATION,
        CATEGORY_DELIMITER_ESCAPE,
        CATEGORY_ENCODED_PAYLOAD,
    }
)

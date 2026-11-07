"""Optional AI layer (MASTERPLAN §5). It only rewords what the rules already found.

The LLM never decides findings, severities or scores (MASTERPLAN §3.3). Everything it
sees comes from `evidence.build_evidence`, and everything it says passes
`grounding.check` before it's shown. Otherwise the built-in texts from `tool.content`
are shown instead.
"""

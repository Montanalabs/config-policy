#! VULNERABLE config-policy — feeds the untrusted input straight to the tool, no extraction.
#! check -> UNSAFE: tainted data cannot reach a capability.
grant applyPolicy

let raw = fetch<web>
privileged { applyPolicy(raw) }  # tainted -> tool: REJECTED

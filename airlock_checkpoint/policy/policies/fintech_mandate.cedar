// Fintech - treasury within its mandate.
// Principal: Agent (.role, .trust_score on a 0-100 scale). Resource: Tool.
// Action: callTool. Tool arguments are exposed under context.args.
//
// The point: identity + trust decide *whether* an agent may move money at all;
// the mandate (an amount ceiling and an approved-payee allowlist) decides
// *which* calls are allowed. Same agent, same tool - allowed inside the limits,
// denied outside them.

// Treasury may wire funds, but only up to the ceiling and only to approved payees.
permit (
    principal,
    action == Action::"callTool",
    resource == Tool::"wire_funds"
)
when {
    principal.role == "treasury" &&
    principal.trust_score >= 75 &&
    context.args.amount <= 10000 &&
    ["ACME-PAYROLL-01"].contains(context.args.account)
};

// Reading the invoice is allowed for any verified agent.
permit (
    principal,
    action == Action::"callTool",
    resource == Tool::"read_invoice"
);

// Absolute ceiling: no single wire above 100000, whatever else would permit it
// (explicit forbid wins).
forbid (
    principal,
    action == Action::"callTool",
    resource == Tool::"wire_funds"
)
when {
    context.args.amount > 100000
};

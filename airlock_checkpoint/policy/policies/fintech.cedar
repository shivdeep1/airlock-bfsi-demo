// Fintech scenario - least privilege for money-movement tools.
// Principal: Agent (.role, .trust_score on a 0-100 scale). Resource: Tool. Action: callTool.

// Treasury agents with sufficient trust may wire funds.
permit (
    principal,
    action == Action::"callTool",
    resource
)
when {
    principal.role == "treasury" &&
    resource == Tool::"wire_funds" &&
    principal.trust_score >= 75
};

// Treasury agents may charge fees.
permit (
    principal,
    action == Action::"callTool",
    resource
)
when {
    principal.role == "treasury" &&
    resource == Tool::"charge_fee"
};

// Read-only tools are allowed for any verified agent.
permit (
    principal,
    action == Action::"callTool",
    resource
)
when {
    resource == Tool::"read_application" || resource == Tool::"get_credit_score"
};

// Belt-and-suspenders: a non-treasury agent may never move money,
// even if some other policy would permit it (explicit forbid wins).
forbid (
    principal,
    action == Action::"callTool",
    resource
)
when {
    (resource == Tool::"wire_funds" || resource == Tool::"charge_fee") &&
    principal.role != "treasury"
};

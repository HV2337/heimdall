"""Output scanning and role-limited detokenization interfaces."""
from gateway.contracts import (CheckedOutput, OutputBlocked, OutputControlError,
                               RequestContext, Role, TokenType, TokenVault)


def allowed_token_types(role: Role, clinical_mode: bool) -> frozenset[TokenType]:
    raise NotImplementedError


def check_output(text: str, canary_values: tuple[str, ...], role: Role,
                 clinical_mode: bool) -> CheckedOutput:
    raise NotImplementedError


def detokenize_output(output: CheckedOutput, context: RequestContext,
                      vault: TokenVault, clinical_mode: bool) -> str:
    raise NotImplementedError

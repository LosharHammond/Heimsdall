"""Framework integrations. Each wraps a framework's tool so every call goes through a ProtectedExecutor."""
from typing import Any, Callable, Optional, Union

ActionPart = Union[str, Callable[[dict], Optional[str]], None]


def resolve(part: ActionPart, args: dict) -> Optional[str]:
    """A fixed string, a template like 'docs/{path}' filled from the tool's arguments, or a function of the arguments."""
    if part is None:
        return None
    if callable(part):
        return part(args)
    try:
        return part.format(**args)
    except (KeyError, IndexError, ValueError):
        return part


def build_action(tool: str, operation: str, args: dict, resource: ActionPart, destination: ActionPart = None, data_classification: Optional[str] = None) -> dict:
    a: dict[str, Any] = {"tool": tool, "operation": operation, "resource": resolve(resource, args) or tool, "args": args}
    dest = resolve(destination, args)
    if dest:
        a["destination"] = dest
    if data_classification:
        a["data_classification"] = data_classification
    return a

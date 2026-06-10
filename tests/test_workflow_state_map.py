from scanner.workflow_state_map import build_state_transition_map


def test_state_transition_map_for_approval_workflow() -> None:
    state_map = build_state_transition_map("approval_rejection", ["http://127.0.0.1:8000/approve"], [{"role_label": "admin"}])
    transitions = state_map["transitions"]
    assert transitions[0]["from_state"] == "pending"
    assert transitions[0]["to_state"] == "approved"
    assert transitions[0]["allowed_roles"] == ["admin"]


def test_state_transition_map_for_checkout_workflow() -> None:
    state_map = build_state_transition_map("checkout_payment", ["http://127.0.0.1:8000/checkout"])
    states = {(item["from_state"], item["to_state"]) for item in state_map["transitions"]}
    assert ("cart", "checkout") in states
    assert ("checkout", "paid") in states

import pytest

from src.validation.config import validate_branches


def test_validate_branches_accepts_canonical_shapes():
    validate_branches({"Acme/App": ["Main", "dev"]})
    validate_branches({"acme/app": "all"})


@pytest.mark.parametrize(
    "value",
    [
        "not-a-dict",
        {"badrepo": ["main"]},
        {"acme/app": "everything"},
        {"acme/app": []},
        {"acme/app": ["../main"]},
        {"acme/app": 42},
    ],
)
def test_validate_branches_rejects_bad_shapes(value):
    with pytest.raises(ValueError):
        validate_branches(value)

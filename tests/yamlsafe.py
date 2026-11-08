"""Copied from robotico-ci/scripts/rci/yamlsafe.py for workflow and action tests.

SafeLoader refuses duplicate keys, anchors, aliases and non-mapping roots; keys remain raw strings as in
GitHub's YAML 1.2. PyYAML is supplied by the supported runners; unittest needs no other dependencies.
"""

try:
    import yaml
except ImportError:  # callers refuse with exit 2
    yaml = None


class YamlError(ValueError):
    pass


if yaml is not None:
    class UniqueKeyLoader(yaml.SafeLoader):
        """SafeLoader that refuses duplicate keys, anchors and aliases and keeps every key a string."""

        def compose_node(self, parent, index):
            if self.check_event(yaml.AliasEvent) or self.peek_event().anchor is not None:
                raise yaml.constructor.ConstructorError(None, None, "anchors and aliases are not allowed",
                                                        self.peek_event().start_mark)
            return super().compose_node(parent, index)

        def construct_mapping(self, node, deep=False):
            seen = set()
            for key, _ in node.value:
                if isinstance(key, yaml.ScalarNode) and not key.tag.endswith(":merge"):
                    if key.value in seen:
                        raise yaml.constructor.ConstructorError(None, None, f"duplicate key {key.value!r}", node.start_mark)
                    seen.add(key.value)
                    key.tag = "tag:yaml.org,2002:str"
            return super().construct_mapping(node, deep)
else:
    UniqueKeyLoader = None


def load(text: str) -> dict:
    """Parses `text` into a mapping; raises YamlError on any problem (invalid, duplicate keys, aliases, non-mapping root)."""
    if yaml is None:
        raise YamlError("PyYAML is missing (apt install python3-yaml)")
    try:
        data = yaml.load(text, Loader=UniqueKeyLoader)  # noqa: S506 - SafeLoader subclass
    except yaml.YAMLError as error:
        raise YamlError(str(error)) from error
    if not isinstance(data, dict):
        raise YamlError("the document is not a mapping")
    return data

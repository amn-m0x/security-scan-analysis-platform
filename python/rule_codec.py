"""YAML/XML transport only. Java owns rule addition, selection and activation."""
import json
import sys
from pathlib import Path
import xml.etree.ElementTree as ET
import yaml


def pack(value):
    if isinstance(value, dict):
        node = ET.Element("map")
        for key, item in value.items():
            if not isinstance(key, str):
                raise ValueError("Rule keys must be strings")
            entry = ET.SubElement(node, "entry", key=key)
            entry.append(pack(item))
        return node
    if isinstance(value, list):
        node = ET.Element("list")
        node.extend(pack(item) for item in value)
        return node
    if value is not None and type(value) not in (str, int, float, bool):
        raise ValueError("Unsupported YAML value")
    node = ET.Element("scalar")
    node.text = json.dumps(value, ensure_ascii=False, allow_nan=False)
    return node


def unpack(node):
    if node.tag == "map":
        return {entry.attrib["key"]: unpack(entry[0]) for entry in node}
    if node.tag == "list":
        return [unpack(item) for item in node]
    if node.tag == "scalar":
        return json.loads(node.text)
    raise ValueError("Unknown transport node")


def main():
    mode, source, destination = sys.argv[1:]
    if mode == "read":
        value = yaml.safe_load(Path(source).read_text(encoding="utf-8"))
        ET.ElementTree(pack(value)).write(destination, encoding="utf-8", xml_declaration=True)
    elif mode == "write":
        value = unpack(ET.parse(source).getroot())
        Path(destination).write_text(yaml.safe_dump(value, allow_unicode=True, sort_keys=False), encoding="utf-8")
    else:
        raise ValueError("Usage: rule_codec.py read|write SOURCE DESTINATION")


if __name__ == "__main__":
    try:
        main()
    except Exception as error:
        print("Rule codec failed:", error, file=sys.stderr)
        sys.exit(1)

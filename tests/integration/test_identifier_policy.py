from __future__ import annotations

import copy
import json
import os
import subprocess
import sys
import tempfile
import textwrap
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, (ROOT / "scripts").as_posix())

from check_identifier_policy import scan_paths  # noqa: E402
from myfuzz.contracts import ContractError, validate_contract  # noqa: E402


class IdentifierPolicyTests(unittest.TestCase):
    def write_source(self, root: Path, relative: str, source: str) -> Path:
        path = root / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(textwrap.dedent(source), encoding="utf-8")
        return path

    def test_explicit_roles_and_protocol_ids_are_allowed(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            source = self.write_source(
                Path(tmp),
                "src/myfuzz/harness/model.py",
                """
                def choose(record, declared_protocol_id):
                    role = record["role"]
                    protocol_id = record["protocol_id"]
                    budget_name = record.get("name")
                    return role, protocol_id == declared_protocol_id, budget_name

                def stable_job_token(target_id):
                    return content_hash({"target_id": target_id}).removeprefix("sha256:")

                def emitted_identifier(identifier):
                    return identifier if identifier[0] == "_" else "escaped"

                GROUPS = ("candidate-direct", "candidate-depaware")
                def aggregate(candidate_id, jobs):
                    selected = [job for job in jobs if job.candidate_id == candidate_id]
                    return [job for job in selected if job.harness in GROUPS]
                """,
            )

            self.assertEqual(scan_paths([source]), [])

    def test_frontend_boundary_is_anchored_to_explicit_repository_root(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            source = self.write_source(
                root,
                "src/myfuzz/scripts/composition_api.py",
                'def bind(record):\n    return record["module_name"]\n',
            )

            untrusted = scan_paths([source])
            trusted = scan_paths([source], repo_root=root)

        self.assertEqual([item.code for item in untrusted], ["raw-identifier-read"])
        self.assertEqual(trusted, [])

    def test_relative_frontend_boundary_path_uses_explicit_repository_root(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            self.write_source(
                root,
                "src/myfuzz/scripts/composition_api.py",
                'def bind(record):\n    return record["module_name"]\n',
            )
            previous = Path.cwd()
            os.chdir(root)
            try:
                violations = scan_paths(
                    [Path("src/myfuzz/scripts/composition_api.py")],
                    repo_root=root,
                )
            finally:
                os.chdir(previous)

        self.assertEqual(violations, [])

    def test_raw_identifier_access_is_rejected_outside_binding_boundary(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            source = self.write_source(
                Path(tmp),
                "src/myfuzz/composition/infer.py",
                """
                def classify(record):
                    return record["module_name"]
                """,
            )

            violations = scan_paths([source])

        self.assertEqual([item.code for item in violations], ["raw-identifier-read"])
        self.assertIn("module_name", violations[0].message)

    def test_identifier_classifiers_are_rejected(self) -> None:
        cases = {
            "comparison": 'return target_id == "ibex"',
            "membership": 'return port_name in {"uart", "gpio"}',
            "prefix": 'return component_id.startswith("cpu_")',
            "regex": 'return re.search(r"irq|timer", instance_name)',
        }
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            for label, statement in cases.items():
                with self.subTest(label=label):
                    source = self.write_source(
                        root,
                        f"src/myfuzz/harness/{label}.py",
                        f"""
                        import re
                        def classify(target_id, port_name, component_id, instance_name):
                            {statement}
                        """,
                    )
                    self.assertTrue(scan_paths([source]))

    def test_aliases_transforms_named_literals_keyword_regex_and_match_are_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            source = self.write_source(
                Path(tmp),
                "src/myfuzz/harness/aliases.py",
                """
                import re
                TARGETS = {"uart", "gpio"}
                RAW_KEY = "port_name"

                def classify(record, port_name):
                    alias = port_name
                    folded = alias.casefold()
                    first = folded == "clock"
                    second = alias in TARGETS
                    third = re.search(pattern=r"irq|timer", string=alias)
                    fourth = record[RAW_KEY]
                    match alias:
                        case "gpio":
                            return first, second, third, fourth
                    return None
                """,
            )

            codes = [item.code for item in scan_paths([source])]

        self.assertIn("identifier-string-comparison", codes)
        self.assertIn("target-keyword-classifier", codes)
        self.assertIn("identifier-regex-classifier", codes)
        self.assertIn("raw-identifier-read", codes)

    def test_control_flow_helper_and_mapping_classifiers_are_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            source = self.write_source(
                Path(tmp),
                "src/myfuzz/harness/control_flow.py",
                """
                TARGETS = {"uart", "gpio"}

                def helper(value):
                    return value == "uart"

                def classify(port_name):
                    loop_result = False
                    for alias in [port_name]:
                        loop_result = alias == "clock"
                    augmented = ""
                    augmented += port_name
                    augmented_result = augmented == "clock"
                    mapping_result = {"uart": 1}.get(port_name)
                    contains_result = any(token in port_name for token in TARGETS)
                    return helper(port_name), loop_result, augmented_result, mapping_result, contains_result
                """,
            )

            codes = [item.code for item in scan_paths([source])]

        self.assertGreaterEqual(codes.count("identifier-string-comparison"), 2)
        self.assertIn("target-keyword-classifier", codes)

    def test_container_and_dunder_access_cannot_clear_python_identifier_taint(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            source = self.write_source(
                Path(tmp),
                "src/myfuzz/harness/container_alias.py",
                """
                def classify(record, port_name):
                    list_alias = [port_name][0]
                    mapping_alias = {"value": port_name}["value"]
                    raw_alias = record.__getitem__("module_name")
                    return (
                        list_alias == "uart",
                        mapping_alias.startswith("cpu_"),
                        raw_alias == "gpio",
                    )
                """,
            )

            codes = [item.code for item in scan_paths([source])]

        self.assertIn("target-keyword-classifier", codes)
        self.assertIn("identifier-affix-classifier", codes)
        self.assertIn("raw-identifier-read", codes)

    def test_comprehension_getter_alias_and_hash_cannot_clear_python_taint(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            source = self.write_source(
                Path(tmp),
                "src/myfuzz/harness/indirect_alias.py",
                """
                def classify(record, port_name):
                    aliases = [item for item in [port_name]]
                    generated = next(item for item in [port_name])
                    getter = record.__getitem__
                    raw = getter("module_name")
                    return (
                        aliases[0] == "uart",
                        generated.startswith("cpu_"),
                        raw == "gpio",
                        content_hash(port_name) == "sha256:known-target",
                    )
                """,
            )

            codes = [item.code for item in scan_paths([source])]

        self.assertGreaterEqual(codes.count("target-keyword-classifier"), 2)
        self.assertIn("identifier-affix-classifier", codes)
        self.assertIn("identifier-string-comparison", codes)
        self.assertIn("raw-identifier-read", codes)

    def test_container_getters_and_mutation_targets_preserve_python_taint(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            source = self.write_source(
                Path(tmp),
                "src/myfuzz/harness/mutated_alias.py",
                """
                def classify(record, port_name):
                    first_getter = [record.__getitem__][0]
                    second_getter, = (record.__getitem__,)
                    first_raw = first_getter("module_name")
                    second_raw = second_getter("port_name")
                    box = {}
                    box["value"] = port_name
                    holder = object()
                    holder.value = port_name
                    return (
                        first_raw == "uart",
                        second_raw == "gpio",
                        box["value"] == "uart",
                        holder.value == "gpio",
                    )
                """,
            )

            codes = [item.code for item in scan_paths([source])]

        self.assertGreaterEqual(codes.count("raw-identifier-read"), 2)
        self.assertGreaterEqual(codes.count("target-keyword-classifier"), 4)

    def test_comprehension_and_stored_getters_preserve_python_taint(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            source = self.write_source(
                Path(tmp),
                "src/myfuzz/harness/stored_getters.py",
                """
                def classify(record, port_name):
                    getter = [item for item in [record.__getitem__]][0]
                    getters = [getter]
                    first = getters[0]("module_name")
                    holder = {}
                    holder["getter"] = record.__getitem__
                    second = holder["getter"]("port_name")
                    holder.getter = record.__getitem__
                    third = holder.getter("instance_name")
                    holder["value"] = ""
                    holder["value"] += port_name
                    return first == "uart", second == "gpio", third == "ibex", holder["value"] == "uart"
                """,
            )

            codes = [item.code for item in scan_paths([source])]

        self.assertGreaterEqual(codes.count("raw-identifier-read"), 3)
        self.assertGreaterEqual(codes.count("target-keyword-classifier"), 4)

    def test_python_mutation_taint_is_field_sensitive(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            source = self.write_source(
                Path(tmp),
                "src/myfuzz/harness/field_sensitive.py",
                """
                def classify(port_name):
                    holder = {}
                    holder["raw"] = port_name
                    return holder["safe"] == "uart"
                """,
            )

            self.assertEqual(scan_paths([source]), [])

    def test_python_access_state_survives_aliases_and_dynamic_keys(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            source = self.write_source(
                Path(tmp),
                "src/myfuzz/harness/aliased_access.py",
                """
                def classify(record, port_name, key):
                    holder = {}
                    holder["raw"] = port_name
                    holder["getter"] = record.__getitem__
                    alias = holder
                    first = alias["getter"]("module_name")
                    dynamic = {}
                    dynamic[key] = port_name
                    return alias["raw"] == "uart", first == "gpio", dynamic["value"] == "ibex"
                """,
            )

            codes = [item.code for item in scan_paths([source])]

        self.assertGreaterEqual(codes.count("raw-identifier-read"), 1)
        self.assertGreaterEqual(codes.count("target-keyword-classifier"), 3)

    def test_python_getter_containers_are_element_sensitive(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            source = self.write_source(
                Path(tmp),
                "src/myfuzz/harness/mixed_getters.py",
                """
                def classify(record, fixed):
                    getters = [record.__getitem__, fixed]
                    value = getters[1]("module_name")
                    return value == "uart"
                """,
            )

            self.assertEqual(scan_paths([source]), [])

    def test_cpp_identifier_access_and_multiline_classifiers_are_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            source = self.write_source(
                Path(tmp),
                "src/myfuzz/harness/classify.cpp",
                r'''
                bool classify(const Record& record, const std::string& portName) {
                    const char* marker = "/* this is data, not a comment */";
                    return record.port_name == "clock" ||
                           portName
                               .starts_with("cpu_") ||
                           std::regex_search(portName, std::regex("irq"));
                }
                ''',
            )

            codes = [item.code for item in scan_paths([source])]

        self.assertIn("raw-identifier-read", codes)
        self.assertIn("identifier-string-comparison", codes)
        self.assertIn("identifier-affix-classifier", codes)
        self.assertIn("identifier-regex-classifier", codes)

    def test_cpp_identifier_subscript_access_is_rejected_outside_literals(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            source = self.write_source(
                Path(tmp),
                "src/myfuzz/harness/subscript_access.cpp",
                r'''
                bool classify(Record& record) {
                    return record["port_name"] == 1 && record[L"module_name"] == 2;
                }
                ''',
            )

            codes = [item.code for item in scan_paths([source])]

        self.assertGreaterEqual(codes.count("raw-identifier-read"), 2)

    def test_cpp_alias_and_raw_string_comparisons_are_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            source = self.write_source(
                Path(tmp),
                "src/myfuzz/harness/alias.cpp",
                r'''
                bool classify(const std::string& portName) {
                    const auto alias = portName;
                    return alias == "clock" || portName == R"(uart)";
                }
                ''',
            )

            codes = [item.code for item in scan_paths([source])]

        self.assertIn("identifier-string-comparison", codes)
        self.assertIn("target-keyword-classifier", codes)

    def test_cpp_transform_call_cannot_clear_identifier_taint(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            source = self.write_source(
                Path(tmp),
                "src/myfuzz/harness/transformed_alias.cpp",
                r'''
                std::string normalize(const std::string& value);
                bool classify(const std::string& portName) {
                    const auto alias = normalize(portName);
                    return alias == "uart";
                }
                ''',
            )

            codes = [item.code for item in scan_paths([source])]

        self.assertIn("target-keyword-classifier", codes)

    def test_cpp_late_assignment_and_brace_init_cannot_clear_identifier_taint(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            source = self.write_source(
                Path(tmp),
                "src/myfuzz/harness/more_aliases.cpp",
                r'''
                std::string normalize(const std::string& value);
                bool classify(const std::string& portName) {
                    std::string late;
                    late = normalize(portName);
                    auto braced{normalize(portName)};
                    return late == "uart" || braced == "gpio";
                }
                ''',
            )

            codes = [item.code for item in scan_paths([source])]

        self.assertGreaterEqual(codes.count("target-keyword-classifier"), 2)

    def test_cpp_paren_method_and_augmented_assignments_preserve_taint(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            source = self.write_source(
                Path(tmp),
                "src/myfuzz/harness/cpp_mutations.cpp",
                r'''
                std::string normalize(const std::string& value);
                bool classify(const std::string& portName) {
                    std::string paren(normalize(portName));
                    std::string assigned;
                    assigned.assign(portName);
                    std::string augmented;
                    augmented += portName;
                    return paren == "uart" || assigned == "gpio" || augmented == "ibex";
                }
                ''',
            )

            codes = [item.code for item in scan_paths([source])]

        self.assertGreaterEqual(codes.count("target-keyword-classifier"), 3)

    def test_cpp_nested_initializers_and_general_mutation_preserve_taint(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            source = self.write_source(
                Path(tmp),
                "src/myfuzz/harness/cpp_nested.cpp",
                r'''
                bool classify(const std::string& portName) {
                    std::string doubled((portName));
                    auto nested{std::string{portName}};
                    std::string appended;
                    appended.append(portName);
                    return doubled == "uart" || nested == "gpio" || appended == "ibex";
                }
                ''',
            )

            codes = [item.code for item in scan_paths([source])]

        self.assertGreaterEqual(codes.count("target-keyword-classifier"), 3)

    def test_cpp_control_and_comma_declarations_preserve_taint(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            source = self.write_source(
                Path(tmp),
                "src/myfuzz/harness/cpp_declarations.cpp",
                r'''
                bool classify(const std::string& portName) {
                    if (auto conditional = portName; conditional == "uart") {}
                    for (std::string loop = portName; loop == "gpio";) { break; }
                    std::string safe, trailing = portName;
                    return trailing == "ibex";
                }
                ''',
            )

            codes = [item.code for item in scan_paths([source])]

        self.assertGreaterEqual(codes.count("target-keyword-classifier"), 3)

    def test_cpp_read_only_methods_do_not_taint_receivers(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            source = self.write_source(
                Path(tmp),
                "src/myfuzz/harness/cpp_read_only.cpp",
                r'''
                bool classify(const std::string& portName) {
                    std::string label = "constant";
                    label.compare(portName);
                    return label == "uart";
                }
                ''',
            )

            self.assertEqual(scan_paths([source]), [])

    def test_cpp_identifier_tokens_inside_literals_do_not_trigger_access_patterns(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            source = self.write_source(
                Path(tmp),
                "src/myfuzz/harness/cpp_pattern_literals.cpp",
                r'''
                bool classify() {
                    std::string raw = ".port_name";
                    std::string affix = "portName.starts_with(\"cpu_\")";
                    std::string regex = "regex_search(portName)";
                    return raw == "literal" && affix == "literal" && regex == "literal";
                }
                ''',
            )

            self.assertEqual(scan_paths([source]), [])

    def test_cpp_identifier_text_inside_literal_does_not_taint_alias(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            source = self.write_source(
                Path(tmp),
                "src/myfuzz/harness/literal_only.cpp",
                r'''
                bool classify() {
                    std::string label = "portName";
                    return label == "uart";
                }
                ''',
            )

            self.assertEqual(scan_paths([source]), [])

    def test_cpp_long_raw_string_content_does_not_taint_alias(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            raw_literal = 'R"tag(' + ("x" * 1100) + '"portName")tag"'
            source = self.write_source(
                Path(tmp),
                "src/myfuzz/harness/long_literal.cpp",
                f'''
                bool classify() {{
                    std::string label = {raw_literal};
                    return label == "uart";
                }}
                ''',
            )

            self.assertEqual(scan_paths([source]), [])

    def test_nested_frontend_boundary_basename_is_not_allowlisted(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            source = self.write_source(
                root,
                "src/myfuzz/frontend/semantic/diagnostics.py",
                'def classify(port_name):\n    return port_name == "uart"\n',
            )

            violations = scan_paths([source], repo_root=root)

        self.assertEqual([item.code for item in violations], ["target-keyword-classifier"])

    def test_symlink_source_is_rejected_without_following_allowlist_target(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            target = self.write_source(
                root,
                "src/myfuzz/scripts/composition_api.py",
                'def bind(record):\n    return record["module_name"]\n',
            )
            link = root / "semantic.py"
            link.symlink_to(target)

            violations = scan_paths([link], repo_root=root)

        self.assertEqual([item.code for item in violations], ["path-symlink"])

    def test_symlink_ancestor_is_rejected_before_boundary_classification(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            actual = base / "actual"
            source = self.write_source(
                actual,
                "src/myfuzz/scripts/composition_api.py",
                'def classify(port_name):\n    return port_name == "uart"\n',
            )
            repository = base / "repository"
            repository.mkdir()
            (repository / "src").symlink_to(actual / "src", target_is_directory=True)
            through_link = repository / source.relative_to(actual)

            violations = scan_paths([through_link], repo_root=repository)

        self.assertEqual([item.code for item in violations], ["path-symlink"])

    def test_frontend_binding_boundary_may_copy_raw_names(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            source = self.write_source(
                root,
                "src/myfuzz/frontend/src/source_map.py",
                """
                def bind(record):
                    return record["module_name"], record.get("port_name")
                """,
            )

            self.assertEqual(scan_paths([source], repo_root=root), [])

    def test_misleading_data_is_opaque_until_code_classifies_it(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            source = self.write_source(
                Path(tmp),
                "src/myfuzz/composition/data.py",
                """
                MISLEADING_FIXTURE = {
                    "opaque_label": "uart_cpu_axi_reset",
                    "role": "target",
                    "protocol_id": "declared-bus",
                }
                """,
            )

            self.assertEqual(scan_paths([source]), [])

    def test_contract_graph_is_name_isomorphic_and_missing_role_is_rejected(self) -> None:
        fixture_path = ROOT / "tests" / "fixtures" / "contracts" / "hdl_facts.v2.valid.json"
        original = json.loads(fixture_path.read_text(encoding="utf-8"))
        original["source_symbols"] = [
            {"id": 1, "name": "diagnostic_alpha", "original_name": "source_alpha"},
            {"id": 2, "name": "diagnostic_beta", "original_name": "source_beta"},
        ]
        renamed = copy.deepcopy(original)
        renamed_count = 0
        for index, symbol in enumerate(renamed["source_symbols"], start=1):
            if "name" in symbol:
                symbol["name"] = f"neutral_{index}"
                renamed_count += 1
            if "original_name" in symbol:
                symbol["original_name"] = f"renamed_{index}"
                renamed_count += 1

        self.assertGreater(renamed_count, 0)

        validate_contract(original, "hdl_facts.v2")
        validate_contract(renamed, "hdl_facts.v2")

        def numeric_graph(document: dict[str, object]) -> tuple[object, ...]:
            return tuple(
                tuple(
                    sorted(
                        (key, value)
                        for key, value in record.items()
                        if key not in {"name", "original_name", "source_name"}
                    )
                )
                for collection in ("modules", "ports", "instances", "pin_bindings", "dataflow_edges")
                for record in document[collection]
            )

        self.assertEqual(numeric_graph(original), numeric_graph(renamed))

        missing_role = copy.deepcopy(original)
        missing_role["ports"][0].pop("declared_role")
        with self.assertRaises(ContractError):
            validate_contract(missing_role, "hdl_facts.v2")

    def test_cli_reports_sorted_violations_and_returns_nonzero(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            self.write_source(
                root,
                "z.py",
                'def classify(port_name):\n    return port_name.endswith("_ready")\n',
            )
            self.write_source(
                root,
                "a.py",
                'def classify(record):\n    return record["target_name"]\n',
            )

            completed = subprocess.run(
                [
                    sys.executable,
                    str(ROOT / "scripts" / "check_identifier_policy.py"),
                    "--paths",
                    str(root),
                ],
                cwd=ROOT,
                capture_output=True,
                text=True,
                check=False,
            )

        self.assertEqual(completed.returncode, 1)
        lines = completed.stdout.splitlines()
        self.assertEqual(lines, sorted(lines))
        self.assertTrue(any("raw-identifier-read" in line for line in lines))
        self.assertTrue(any("identifier-affix-classifier" in line for line in lines))


if __name__ == "__main__":
    unittest.main()

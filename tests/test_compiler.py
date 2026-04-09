"""Tests for core/compiler.py — field loading, transforms, and output."""

from __future__ import annotations


import pytest

from core.compiler import (
    BaseCompiler,
    CsvCompiler,
    ExcelCompiler,
    _apply_transforms,
    _coerce,
    _get_nested,
    _instantiate_transforms,
    build_dataframe,
    load_fields_config,
)
from core.models import (
    AlertData,
    FieldDefinition,
    FieldType,
    FieldsConfig,
    RepoData,
    RepoDetails,
)
from core.transforms import BaseTransform, FlagTransform, TimestampTransform
from tests.conftest import MockStorage


# ── _get_nested ───────────────────────────────────────────────────────


class TestGetNested:
    def test_simple_key(self):
        assert _get_nested({"a": 1}, "a") == 1

    def test_dot_path(self):
        assert _get_nested({"a": {"b": {"c": 3}}}, "a.b.c") == 3

    def test_missing_key_returns_default(self):
        assert _get_nested({"a": 1}, "b") is None
        assert _get_nested({"a": 1}, "b", "fallback") == "fallback"

    def test_missing_nested_returns_default(self):
        assert _get_nested({"a": {"b": 1}}, "a.c") is None

    def test_non_dict_intermediate(self):
        assert _get_nested({"a": 42}, "a.b") is None


# ── _coerce ───────────────────────────────────────────────────────────


class TestCoerce:
    def _field(self, type: FieldType, default=None) -> FieldDefinition:
        return FieldDefinition(source="x", column="X", type=type, default=default)

    def test_string(self):
        assert _coerce("hello", self._field(FieldType.string)) == "hello"

    def test_string_from_int(self):
        assert _coerce(42, self._field(FieldType.string)) == "42"

    def test_integer(self):
        assert _coerce("42", self._field(FieldType.integer)) == 42

    def test_integer_invalid_returns_default(self):
        assert _coerce("abc", self._field(FieldType.integer, default=-1)) == -1

    def test_boolean(self):
        assert _coerce(True, self._field(FieldType.boolean)) is True
        assert _coerce(1, self._field(FieldType.boolean)) is True
        assert _coerce(0, self._field(FieldType.boolean)) is False

    def test_date_iso_format(self):
        result = _coerce("2024-06-15T12:30:00Z", self._field(FieldType.date))
        assert result == "2024-06-15"

    def test_date_invalid_returns_str(self):
        result = _coerce("not-a-date", self._field(FieldType.date))
        assert result == "not-a-date"

    def test_json(self):
        result = _coerce({"a": 1}, self._field(FieldType.json))
        assert '"a"' in result  # JSON string

    def test_none_returns_default(self):
        assert _coerce(None, self._field(FieldType.string, default="N/A")) == "N/A"

    def test_none_returns_none_default(self):
        assert _coerce(None, self._field(FieldType.string)) is None


# ── load_fields_config ────────────────────────────────────────────────


class TestLoadFieldsConfig:
    def test_loads_valid_yaml(self, tmp_path):
        yaml_file = tmp_path / "fields.yaml"
        yaml_file.write_text(
            "fields:\n"
            "  - source: repo_details.name\n"
            "    column: Name\n"
            "    type: string\n"
            "  - source: alerts.dependabot_alerts\n"
            "    column: Dependabot Alerts\n"
            "    type: integer\n"
            "    default: 0\n"
        )
        config = load_fields_config(yaml_file)
        assert isinstance(config, FieldsConfig)
        assert len(config.fields) == 2
        assert config.fields[0].source == "repo_details.name"
        assert config.fields[1].default == 0

    def test_missing_file_raises(self, tmp_path):
        with pytest.raises(FileNotFoundError):
            load_fields_config(tmp_path / "nonexistent.yaml")

    def test_invalid_type_raises(self, tmp_path):
        yaml_file = tmp_path / "fields.yaml"
        yaml_file.write_text(
            "fields:\n  - source: a\n    column: A\n    type: badtype\n"
        )
        from pydantic import ValidationError

        with pytest.raises(ValidationError):
            load_fields_config(yaml_file)


# ── _apply_transforms ─────────────────────────────────────────────────


class TestApplyTransforms:
    def test_applies_in_order(self):
        data = RepoData(
            repo_details=RepoDetails(
                full_name="o/r",
                name="r",
                pushed_at="2020-01-01T00:00:00Z",
            )
        )
        transforms = [TimestampTransform(), FlagTransform()]
        result = _apply_transforms(data, transforms)
        assert result.days_since_push is not None
        assert "stale" in result.flags

    def test_transform_error_does_not_crash(self):
        class BrokenTransform(BaseTransform):
            @property
            def name(self):
                return "broken"

            def apply(self, data):
                raise ValueError("kaboom")

        data = RepoData()
        result = _apply_transforms(data, [BrokenTransform()])
        # Should return the original data despite the error
        assert isinstance(result, RepoData)


class TestInstantiateTransforms:
    def test_instantiates_transform_classes(self):
        transforms = _instantiate_transforms([TimestampTransform])

        assert len(transforms) == 1
        assert isinstance(transforms[0], TimestampTransform)

    def test_preserves_transform_instances(self):
        transforms = _instantiate_transforms([TimestampTransform()])

        assert len(transforms) == 1
        assert isinstance(transforms[0], TimestampTransform)

    def test_invalid_transform_raises(self):
        with pytest.raises(TypeError):
            _instantiate_transforms([object()])


# ── build_dataframe ──────────────────────────────────────────────────


class TestBuildDataframe:
    def _simple_config(self) -> FieldsConfig:
        return FieldsConfig(
            fields=[
                FieldDefinition(
                    source="repo_details.full_name",
                    column="Repo",
                    type=FieldType.string,
                ),
                FieldDefinition(
                    source="alerts.dependabot_alerts",
                    column="Dependabot",
                    type=FieldType.integer,
                    default=0,
                ),
            ]
        )

    def test_empty_storage(self):
        storage = MockStorage()
        df = build_dataframe(storage, self._simple_config(), transforms=[])
        assert len(df) == 0

    def test_single_row(self):
        storage = MockStorage()
        storage.upsert(
            "org/repo",
            RepoData(
                repo_details=RepoDetails(full_name="org/repo", name="repo"),
                alerts=AlertData(dependabot_alerts=5),
            ),
        )
        df = build_dataframe(storage, self._simple_config(), transforms=[])
        assert len(df) == 1
        assert df.iloc[0]["Repo"] == "org/repo"
        assert df.iloc[0]["Dependabot"] == 5

    def test_missing_field_uses_default(self):
        storage = MockStorage()
        storage.upsert("org/repo", RepoData())  # no alerts
        df = build_dataframe(storage, self._simple_config(), transforms=[])
        assert df.iloc[0]["Dependabot"] == 0

    def test_with_transforms(self):
        config = FieldsConfig(
            fields=[
                FieldDefinition(
                    source="days_since_push",
                    column="Days",
                    type=FieldType.integer,
                    default=0,
                ),
            ]
        )
        storage = MockStorage()
        storage.upsert(
            "org/repo",
            RepoData(
                repo_details=RepoDetails(
                    full_name="org/repo",
                    name="repo",
                    pushed_at="2020-01-01T00:00:00Z",
                ),
            ),
        )
        df = build_dataframe(storage, config, transforms=[TimestampTransform()])
        assert df.iloc[0]["Days"] > 365

    def test_with_transform_classes(self):
        config = FieldsConfig(
            fields=[
                FieldDefinition(
                    source="days_since_push",
                    column="Days",
                    type=FieldType.integer,
                    default=0,
                ),
            ]
        )
        storage = MockStorage()
        storage.upsert(
            "org/repo",
            RepoData(
                repo_details=RepoDetails(
                    full_name="org/repo",
                    name="repo",
                    pushed_at="2020-01-01T00:00:00Z",
                ),
            ),
        )
        df = build_dataframe(storage, config, transforms=[TimestampTransform])
        assert df.iloc[0]["Days"] > 365

    def test_multiple_rows(self):
        storage = MockStorage()
        for i in range(3):
            storage.upsert(
                f"org/repo-{i}",
                RepoData(
                    repo_details=RepoDetails(
                        full_name=f"org/repo-{i}", name=f"repo-{i}"
                    ),
                ),
            )
        df = build_dataframe(storage, self._simple_config(), transforms=[])
        assert len(df) == 3


# ── BaseCompiler ──────────────────────────────────────────────────────


class TestBaseCompiler:
    def test_cannot_instantiate(self):
        with pytest.raises(TypeError):
            BaseCompiler()


# ── CsvCompiler ──────────────────────────────────────────────────────


class TestCsvCompiler:
    def test_writes_csv(self, tmp_path):
        storage = MockStorage()
        storage.upsert(
            "org/repo",
            RepoData(
                repo_details=RepoDetails(full_name="org/repo", name="repo"),
                alerts=AlertData(dependabot_alerts=2),
            ),
        )
        config = FieldsConfig(
            fields=[
                FieldDefinition(
                    source="repo_details.name", column="Name", type=FieldType.string
                ),
                FieldDefinition(
                    source="alerts.dependabot_alerts",
                    column="Alerts",
                    type=FieldType.integer,
                    default=0,
                ),
            ]
        )
        output = tmp_path / "output.csv"
        CsvCompiler().compile(storage, output, config)

        assert output.exists()
        content = output.read_text()
        assert "Name" in content
        assert "repo" in content

    def test_format_name(self):
        assert CsvCompiler().format_name == "csv"

    def test_accepts_explicit_transforms(self, tmp_path):
        storage = MockStorage()
        storage.upsert(
            "org/repo",
            RepoData(
                repo_details=RepoDetails(
                    full_name="org/repo",
                    name="repo",
                    pushed_at="2020-01-01T00:00:00Z",
                ),
            ),
        )
        config = FieldsConfig(
            fields=[
                FieldDefinition(
                    source="days_since_push",
                    column="Days",
                    type=FieldType.integer,
                    default=0,
                ),
            ]
        )
        output = tmp_path / "output.csv"

        CsvCompiler().compile(
            storage,
            output,
            config,
            transforms=[TimestampTransform()],
        )

        content = output.read_text(encoding="utf-8")
        assert "Days" in content
        assert len(content.splitlines()) == 2

    def test_write_rows_empty_creates_empty_file(self, tmp_path):
        output = tmp_path / "rows.csv"
        written = CsvCompiler.write_rows(output, [])

        assert written == 0
        assert output.exists()
        assert output.read_text(encoding="utf-8") == ""

    def test_write_rows_preserves_first_seen_columns(self, tmp_path):
        output = tmp_path / "rows.csv"
        rows = [{"a": 1, "b": 2}, {"b": 3, "c": 4}]

        written = CsvCompiler.write_rows(output, rows)
        content = output.read_text(encoding="utf-8").splitlines()

        assert written == 2
        assert content[0] == "a,b,c"
        assert content[1] == "1,2,"
        assert content[2] == ",3,4"


# ── ExcelCompiler ────────────────────────────────────────────────────


class TestExcelCompiler:
    def test_format_name(self):
        assert ExcelCompiler().format_name == "excel"

    def test_writes_xlsx(self, tmp_path):
        openpyxl = pytest.importorskip("openpyxl")
        storage = MockStorage()
        storage.upsert(
            "org/repo",
            RepoData(
                repo_details=RepoDetails(full_name="org/repo", name="repo"),
            ),
        )
        config = FieldsConfig(
            fields=[
                FieldDefinition(
                    source="repo_details.name", column="Name", type=FieldType.string
                ),
            ]
        )
        output = tmp_path / "output.xlsx"
        ExcelCompiler().compile(storage, output, config)
        assert output.exists()
        assert output.stat().st_size > 0

    def test_accepts_explicit_transforms(self, tmp_path):
        pytest.importorskip("openpyxl")
        storage = MockStorage()
        storage.upsert(
            "org/repo",
            RepoData(
                repo_details=RepoDetails(
                    full_name="org/repo",
                    name="repo",
                    pushed_at="2020-01-01T00:00:00Z",
                ),
            ),
        )
        config = FieldsConfig(
            fields=[
                FieldDefinition(
                    source="days_since_push",
                    column="Days",
                    type=FieldType.integer,
                    default=0,
                ),
            ]
        )
        output = tmp_path / "output.xlsx"

        ExcelCompiler().compile(
            storage,
            output,
            config,
            transforms=[TimestampTransform()],
        )

        assert output.exists()
        assert output.stat().st_size > 0

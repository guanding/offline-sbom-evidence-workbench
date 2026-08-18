"""Safe, read-only compatibility adapter for the PRO-03B XLSX template.

Workbook rows remain manual/supplier claims.  This adapter never treats them
as proof that a component was present in a particular build.
"""

from __future__ import annotations

import hashlib
import io
import os
import re
import stat
import xml.etree.ElementTree as ET
import zipfile
from pathlib import Path, PurePosixPath
from typing import Any


class ExcelImportError(ValueError):
    """Raised when an XLSX package is unsafe or outside the supported template."""


MAX_XLSX_BYTES = 20 * 1024 * 1024
MAX_ENTRIES = 512
MAX_EXPANDED_BYTES = 64 * 1024 * 1024
MAX_XML_BYTES = 16 * 1024 * 1024
MAX_WORKSHEET_ROWS = 10_000
MAX_WORKSHEET_COLUMNS = 64
MAX_WORKSHEET_CELLS = 100_000
NS = {"m": "http://schemas.openxmlformats.org/spreadsheetml/2006/main"}
REL_NS = {"r": "http://schemas.openxmlformats.org/package/2006/relationships"}
OFFICE_REL_NS = "http://schemas.openxmlformats.org/officeDocument/2006/relationships"

EXPECTED_HEADERS = {
    "01_Metadata_元数据": (
        "Field 字段",
        "Customer entry 客户填写",
        "Example 示例",
        "Notes 说明",
    ),
    "02_SBOM_Software": (
        "Row ID 行号",
        "Component category 组件类别",
        "Component producer 组件生产者",
        "Component name 组件名称",
        "Component version 组件版本",
        "Unique identifier PURL/CPE/Internal ID 唯一标识",
        "Dependency relationship 依赖关系",
        "Source / Evidence 来源/证据",
        "Used in product build 是否进入目标构建",
        "Security relevance 安全相关性",
        "Known uncertainty / gap 已知不确定性/缺口",
        "Customer notes 客户备注",
    ),
    "03_HBOM_Hardware": (
        "Row ID 行号",
        "Hardware category 硬件类别",
        "Manufacturer 制造商",
        "Component / Part name 组件/部件名称",
        "Part number / ID 部件号/标识",
        "Hardware revision 硬件修订",
        "Applicable firmware 适用固件",
        "Security role 安全作用",
        "Supplier support / EoS 供应商支持/EoS",
        "Source / Evidence 来源/证据",
        "Known uncertainty / gap 已知不确定性/缺口",
        "Customer notes 客户备注",
    ),
}


def _safe_package_path(name: str) -> str:
    if not name or "\\" in name or "\x00" in name:
        raise ExcelImportError("XLSX contains an unsafe package path")
    path = PurePosixPath(name)
    if path.is_absolute() or path.as_posix() != name or any(part in {"", ".", ".."} for part in path.parts):
        raise ExcelImportError("XLSX contains a non-canonical package path")
    return name


def _xml(payload: bytes, label: str) -> ET.Element:
    if len(payload) > MAX_XML_BYTES:
        raise ExcelImportError(f"XLSX XML exceeds the size limit: {label}")
    upper = payload.upper()
    if b"<!DOCTYPE" in upper or b"<!ENTITY" in upper:
        raise ExcelImportError(f"DTD/entity is forbidden in XLSX XML: {label}")
    try:
        return ET.fromstring(payload)
    except ET.ParseError as exc:
        raise ExcelImportError(f"invalid XLSX XML: {label}") from exc


def _load_parts(path: Path) -> tuple[dict[str, bytes], str]:
    path = Path(path)
    try:
        descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    except OSError as exc:
        raise ExcelImportError("XLSX cannot be read") from exc
    try:
        info = os.fstat(descriptor)
        if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or info.st_size > MAX_XLSX_BYTES:
            raise ExcelImportError("XLSX must be one bounded, single-link regular file")
        with os.fdopen(descriptor, "rb", closefd=False) as handle:
            payload = handle.read(MAX_XLSX_BYTES + 1)
        if len(payload) != info.st_size or len(payload) > MAX_XLSX_BYTES:
            raise ExcelImportError("XLSX changed while it was being read")
    finally:
        os.close(descriptor)
    digest = hashlib.sha256(payload).hexdigest()
    try:
        with zipfile.ZipFile(io.BytesIO(payload)) as archive:
            entries = archive.infolist()
            if len(entries) > MAX_ENTRIES:
                raise ExcelImportError("XLSX contains too many package entries")
            names: set[str] = set()
            expanded = 0
            parts: dict[str, bytes] = {}
            for entry in entries:
                name = _safe_package_path(entry.filename)
                if name in names:
                    raise ExcelImportError("XLSX contains a duplicate package path")
                names.add(name)
                if entry.flag_bits & 0x1:
                    raise ExcelImportError("encrypted XLSX entries are unsupported")
                unix_mode = (entry.external_attr >> 16) & 0xFFFF
                if unix_mode and stat.S_IFMT(unix_mode) not in {0, stat.S_IFREG, stat.S_IFDIR}:
                    raise ExcelImportError("non-regular XLSX ZIP entries are forbidden")
                expanded += entry.file_size
                if expanded > MAX_EXPANDED_BYTES:
                    raise ExcelImportError("XLSX expanded content exceeds the size limit")
                if entry.compress_size and entry.file_size > 1_000_000 and entry.file_size / entry.compress_size > 200:
                    raise ExcelImportError("XLSX compression ratio exceeds the safety limit")
                lower = name.lower()
                if "vbaproject" in lower or lower.startswith("xl/externallinks/") or lower.endswith(".bin"):
                    raise ExcelImportError("macros, binary objects, and external workbook links are forbidden")
                if not entry.is_dir():
                    parts[name] = archive.read(entry)
    except (OSError, zipfile.BadZipFile, RuntimeError) as exc:
        raise ExcelImportError("file is not a readable XLSX ZIP package") from exc
    return parts, digest


def _shared_strings(parts: dict[str, bytes]) -> list[str]:
    payload = parts.get("xl/sharedStrings.xml")
    if payload is None:
        return []
    root = _xml(payload, "xl/sharedStrings.xml")
    values: list[str] = []
    for item in root.findall("m:si", NS):
        values.append("".join(node.text or "" for node in item.iterfind(".//m:t", NS)))
    return values


def _sheet_targets(parts: dict[str, bytes]) -> dict[str, str]:
    workbook = _xml(parts.get("xl/workbook.xml", b""), "xl/workbook.xml")
    relationships = _xml(
        parts.get("xl/_rels/workbook.xml.rels", b""),
        "xl/_rels/workbook.xml.rels",
    )
    target_by_id: dict[str, str] = {}
    for relationship in relationships.findall("r:Relationship", REL_NS):
        if relationship.get("TargetMode") == "External":
            raise ExcelImportError("external workbook relationship is forbidden")
        identifier = relationship.get("Id")
        target = relationship.get("Target")
        if not identifier or not target:
            raise ExcelImportError("workbook relationship is incomplete")
        normalized = target.lstrip("/")
        if not normalized.startswith("xl/"):
            normalized = "xl/" + normalized
        target_by_id[identifier] = _safe_package_path(normalized)
    result: dict[str, str] = {}
    relationship_key = f"{{{OFFICE_REL_NS}}}id"
    for sheet in workbook.findall("m:sheets/m:sheet", NS):
        name = sheet.get("name")
        relationship_id = sheet.get(relationship_key)
        if not name or relationship_id not in target_by_id:
            raise ExcelImportError("workbook sheet relationship is incomplete")
        result[name] = target_by_id[relationship_id]
    return result


def _cell_coordinates(reference: str) -> tuple[int, int]:
    match = re.fullmatch(r"([A-Z]+)([1-9][0-9]*)", reference)
    if not match:
        raise ExcelImportError("worksheet contains an invalid cell reference")
    number = 0
    for character in match.group(1):
        number = number * 26 + ord(character) - 64
    row_number = int(match.group(2))
    if number > MAX_WORKSHEET_COLUMNS or row_number > MAX_WORKSHEET_ROWS:
        raise ExcelImportError("worksheet cell is outside the supported bounded template range")
    return number, row_number


def _sheet_rows(payload: bytes, shared: list[str], label: str) -> list[list[str | None]]:
    root = _xml(payload, label)
    rows: list[list[str | None]] = []
    seen_cells: set[str] = set()
    seen_rows: set[int] = set()
    cell_count = 0
    for raw_row in root.findall("m:sheetData/m:row", NS):
        if len(rows) >= MAX_WORKSHEET_ROWS:
            raise ExcelImportError("worksheet contains too many rows")
        raw_row_number = raw_row.get("r")
        if raw_row_number is None or not raw_row_number.isascii() or not raw_row_number.isdigit():
            raise ExcelImportError("worksheet row has an invalid reference")
        row_number = int(raw_row_number)
        if row_number < 1 or row_number > MAX_WORKSHEET_ROWS or row_number in seen_rows:
            raise ExcelImportError("worksheet row reference is duplicate or out of range")
        seen_rows.add(row_number)
        values: dict[int, str | None] = {}
        for cell in raw_row.findall("m:c", NS):
            cell_count += 1
            if cell_count > MAX_WORKSHEET_CELLS:
                raise ExcelImportError("worksheet contains too many cells")
            if cell.find("m:f", NS) is not None:
                raise ExcelImportError("formulas are forbidden in imported workbook data")
            reference = cell.get("r")
            if reference is None:
                raise ExcelImportError("worksheet cell has no reference")
            if reference in seen_cells:
                raise ExcelImportError("worksheet contains a duplicate cell reference")
            seen_cells.add(reference)
            column, cell_row = _cell_coordinates(reference)
            if cell_row != row_number:
                raise ExcelImportError("worksheet cell row does not match its row container")
            cell_type = cell.get("t")
            value_node = cell.find("m:v", NS)
            if cell_type == "inlineStr":
                value = "".join(node.text or "" for node in cell.iterfind(".//m:t", NS))
            elif value_node is None:
                value = None
            elif cell_type == "s":
                try:
                    index = int(value_node.text or "")
                except ValueError as exc:
                    raise ExcelImportError("shared string reference is invalid") from exc
                if index < 0:
                    raise ExcelImportError("shared string reference must be non-negative")
                try:
                    value = shared[index]
                except IndexError as exc:
                    raise ExcelImportError("shared string reference is invalid") from exc
            else:
                value = value_node.text
            values[column] = value
        width = max(values, default=0)
        rows.append([values.get(index) for index in range(1, width + 1)])
    return rows


def import_pro03b(path: Path) -> dict[str, Any]:
    """Parse the supported fields without promoting them to build evidence."""

    parts, workbook_sha256 = _load_parts(Path(path))
    targets = _sheet_targets(parts)
    missing = sorted(set(EXPECTED_HEADERS) - set(targets))
    if missing:
        raise ExcelImportError(f"required PRO-03B sheets are missing: {missing}")
    shared = _shared_strings(parts)
    sheets: dict[str, list[list[str | None]]] = {}
    for name in EXPECTED_HEADERS:
        target = targets[name]
        if target not in parts:
            raise ExcelImportError(f"worksheet payload is missing: {name}")
        sheets[name] = _sheet_rows(parts[target], shared, target)
        observed_header = tuple((sheets[name][0] + [None] * len(EXPECTED_HEADERS[name]))[: len(EXPECTED_HEADERS[name])])
        if observed_header != EXPECTED_HEADERS[name]:
            raise ExcelImportError(f"PRO-03B header does not match template v1.4: {name}")

    metadata: dict[str, str] = {}
    for row in sheets["01_Metadata_元数据"][1:]:
        if len(row) >= 2 and row[0] and row[1]:
            metadata[row[0]] = row[1]

    def claims(sheet_name: str) -> list[dict[str, Any]]:
        headers = EXPECTED_HEADERS[sheet_name]
        result: list[dict[str, Any]] = []
        for row in sheets[sheet_name][1:]:
            padded = (row + [None] * len(headers))[: len(headers)]
            if not any(value not in (None, "") for value in padded):
                continue
            result.append(
                {
                    "claim_classification": "MANUAL_OR_SUPPLIER_CLAIM_NOT_BUILD_PROOF",
                    "fields": {header: value for header, value in zip(headers, padded)},
                }
            )
        return result

    required_metadata = (
        "Product name 产品名称",
        "Product version 产品版本",
        "Hardware revision 硬件修订",
        "Build ID 构建号",
    )
    return {
        "schema_version": "1.0",
        "classification": "CUSTOMER_TEMPLATE_INPUT_NOT_BUILD_EVIDENCE",
        "template_profile": "PRO-03B-v1.4",
        "input_sha256": workbook_sha256,
        "intake_status": (
            "MANUAL_CLAIMS_READY_FOR_REVIEW"
            if all(metadata.get(field) for field in required_metadata)
            else "TEMPLATE_OR_INCOMPLETE_CUSTOMER_INPUT"
        ),
        "metadata": metadata,
        "software_claims": claims("02_SBOM_Software"),
        "hardware_claims": claims("03_HBOM_Hardware"),
        "build_inclusion_proven": False,
        "boundary": (
            "Imported rows are manual or supplier claims only. They do not prove release inclusion, "
            "component population completeness, PRE-7 conformity, CRA conformity, or approval."
        ),
    }

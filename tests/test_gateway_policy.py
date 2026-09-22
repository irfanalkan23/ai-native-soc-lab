"""Unit tests for gateway policy engine and validation boundaries."""

import unittest

from gateway.policy import (
    ALLOWED_FIELDS,
    ALLOWED_HOSTS,
    ALLOWED_QUERY_TYPES,
    PolicyValidationError,
    SearchRequest,
    build_allowlisted_spl,
    validate_search_request,
)


class TestGatewayPolicy(unittest.TestCase):
    """Test policy boundary enforcement and input sanitization."""

    def test_valid_request(self) -> None:
        """Verify that compliant parameters create a valid SearchRequest."""
        req = validate_search_request(
            query_type="encoded_powershell_matches",
            host="DC01",
            minutes=15,
            limit=10,
        )
        self.assertIsInstance(req, SearchRequest)
        self.assertEqual(req.query_type, "encoded_powershell_matches")
        self.assertEqual(req.host, "DC01")
        self.assertEqual(req.minutes, 15)
        self.assertEqual(req.limit, 10)

    def test_direct_search_request_instantiation_validation(self) -> None:
        """Proof: Direct SearchRequest construction enforces policy invariants."""
        # Invalid query_type
        with self.assertRaises(PolicyValidationError):
            SearchRequest(
                query_type="unauthorized_type",
                host="DC01",
                minutes=15,
                limit=10,
            )
        # Invalid host
        with self.assertRaises(PolicyValidationError):
            SearchRequest(
                query_type="encoded_powershell_matches",
                host="WORKSTATION1",
                minutes=15,
                limit=10,
            )
        # Invalid minutes
        with self.assertRaises(PolicyValidationError):
            SearchRequest(
                query_type="encoded_powershell_matches",
                host="DC01",
                minutes=0,
                limit=10,
            )
        # Invalid limit
        with self.assertRaises(PolicyValidationError):
            SearchRequest(
                query_type="encoded_powershell_matches",
                host="DC01",
                minutes=15,
                limit=99,
            )

    def test_build_allowlisted_spl_defense_in_depth(self) -> None:
        """Proof: build_allowlisted_spl cannot be used to inject an unchecked host/minutes/limit."""
        # Non-SearchRequest object rejected
        with self.assertRaises(PolicyValidationError):
            build_allowlisted_spl("search index=*")  # type: ignore[arg-type]

        # Valid SearchRequest succeeds
        valid_req = SearchRequest(
            query_type="encoded_powershell_matches",
            host="DC01",
            minutes=15,
            limit=10,
        )
        spl = build_allowlisted_spl(valid_req)
        self.assertTrue(spl.startswith("search index=main"))

        # Even if object.__setattr__ is abused to mutate a frozen dataclass, re-validation catches it
        object.__setattr__(valid_req, "host", 'DC01" OR index=* |')
        with self.assertRaises(PolicyValidationError):
            build_allowlisted_spl(valid_req)

    def test_regression_boolean_coercion_cannot_succeed_through_builder(self) -> None:
        """Regression test: minutes=True and limit=True cannot succeed through builder or validation."""
        # Case 1: Caller attempts to create request with minutes=True
        with self.assertRaises(PolicyValidationError):
            validate_search_request(
                query_type="encoded_powershell_matches",
                host="DC01",
                minutes=True,  # type: ignore[arg-type]
                limit=10,
            )

        # Case 2: Caller attempts to create request with limit=True
        with self.assertRaises(PolicyValidationError):
            validate_search_request(
                query_type="encoded_powershell_matches",
                host="DC01",
                minutes=15,
                limit=True,  # type: ignore[arg-type]
            )

        # Case 3: Direct instantiation of SearchRequest with booleans
        with self.assertRaises(PolicyValidationError):
            SearchRequest(
                query_type="encoded_powershell_matches",
                host="DC01",
                minutes=True,  # type: ignore[arg-type]
                limit=10,
            )
        with self.assertRaises(PolicyValidationError):
            SearchRequest(
                query_type="encoded_powershell_matches",
                host="DC01",
                minutes=15,
                limit=True,  # type: ignore[arg-type]
            )

        # Case 4: Passing a tampered request with booleans to build_allowlisted_spl
        req = SearchRequest(
            query_type="encoded_powershell_matches",
            host="DC01",
            minutes=15,
            limit=10,
        )
        object.__setattr__(req, "minutes", True)
        with self.assertRaises(PolicyValidationError):
            build_allowlisted_spl(req)

        object.__setattr__(req, "minutes", 15)
        object.__setattr__(req, "limit", True)
        with self.assertRaises(PolicyValidationError):
            build_allowlisted_spl(req)

    def test_invalid_host(self) -> None:
        """Verify that unallowlisted hosts are rejected."""
        invalid_hosts = ["DC02", "WORKSTATION01", "dc01", "", "192.168.1.100", "localhost"]
        for host in invalid_hosts:
            with self.subTest(host=host):
                with self.assertRaises(PolicyValidationError):
                    validate_search_request(
                        query_type="encoded_powershell_matches",
                        host=host,
                        minutes=15,
                        limit=10,
                    )

    def test_minutes_zero(self) -> None:
        """Verify that minutes=0 is rejected (minimum is 1)."""
        with self.assertRaises(PolicyValidationError):
            validate_search_request(
                query_type="encoded_powershell_matches",
                host="DC01",
                minutes=0,
                limit=10,
            )

    def test_minutes_greater_than_sixty(self) -> None:
        """Verify that minutes>60 is rejected (maximum is 60)."""
        with self.assertRaises(PolicyValidationError):
            validate_search_request(
                query_type="encoded_powershell_matches",
                host="DC01",
                minutes=61,
                limit=10,
            )

    def test_limit_zero(self) -> None:
        """Verify that limit=0 is rejected (minimum is 1)."""
        with self.assertRaises(PolicyValidationError):
            validate_search_request(
                query_type="encoded_powershell_matches",
                host="DC01",
                minutes=15,
                limit=0,
            )

    def test_limit_greater_than_fifty(self) -> None:
        """Verify that limit>50 is rejected (maximum is 50)."""
        with self.assertRaises(PolicyValidationError):
            validate_search_request(
                query_type="encoded_powershell_matches",
                host="DC01",
                minutes=15,
                limit=51,
            )

    def test_unknown_query_type(self) -> None:
        """Verify that arbitrary or unknown query types are rejected."""
        unauthorized_types = ["arbitrary_spl", "process_create", "", "encoded_powershell", None]
        for qtype in unauthorized_types:
            with self.subTest(query_type=qtype):
                with self.assertRaises(PolicyValidationError):
                    validate_search_request(
                        query_type=qtype,  # type: ignore[arg-type]
                        host="DC01",
                        minutes=15,
                        limit=10,
                    )

    def test_arbitrary_spl_injection_prevention_via_host(self) -> None:
        """Proof: Caller cannot inject SPL syntax through the host parameter."""
        injection_payloads = [
            'DC01" OR index=* |',
            'DC01 | delete',
            'DC01" index=secrets | eval leaked=1 | ',
            'DC01; eval x=1',
            'DC01\n| table *',
        ]
        for payload in injection_payloads:
            with self.subTest(payload=payload):
                with self.assertRaises(PolicyValidationError):
                    validate_search_request(
                        query_type="encoded_powershell_matches",
                        host=payload,
                        minutes=15,
                        limit=10,
                    )

    def test_arbitrary_spl_injection_prevention_via_numeric_params(self) -> None:
        """Proof: String payloads cannot be passed to minutes or limit."""
        with self.assertRaises(PolicyValidationError):
            validate_search_request(
                query_type="encoded_powershell_matches",
                host="DC01",
                minutes="15 | eval injected=1",  # type: ignore[arg-type]
                limit=10,
            )
        with self.assertRaises(PolicyValidationError):
            validate_search_request(
                query_type="encoded_powershell_matches",
                host="DC01",
                minutes=15,
                limit="10 | head 999",  # type: ignore[arg-type]
            )

    def test_boolean_coercion_prevention(self) -> None:
        """Proof: Python boolean types are not coerced into integers."""
        with self.assertRaises(PolicyValidationError):
            validate_search_request(
                query_type="encoded_powershell_matches",
                host="DC01",
                minutes=True,  # type: ignore[arg-type]
                limit=10,
            )
        with self.assertRaises(PolicyValidationError):
            validate_search_request(
                query_type="encoded_powershell_matches",
                host="DC01",
                minutes=15,
                limit=False,  # type: ignore[arg-type]
            )

    def test_caller_cannot_change_index(self) -> None:
        """Proof: Caller cannot supply an index parameter or redirect search index."""
        # validate_search_request does not accept index parameter
        with self.assertRaises(TypeError):
            validate_search_request(
                query_type="encoded_powershell_matches",
                host="DC01",
                minutes=15,
                limit=10,
                index="other_index",  # type: ignore[call-arg]
            )

        req = validate_search_request(
            query_type="encoded_powershell_matches",
            host="DC01",
            minutes=15,
            limit=10,
        )
        spl = build_allowlisted_spl(req)
        # Verify generated SPL strictly anchors to index=main and sourcetype
        self.assertIn("index=main", spl)
        self.assertIn('sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational"', spl)

    def test_spl_construction_correctness(self) -> None:
        """Verify that the generated SPL matches the verified detection template."""
        req = SearchRequest(
            query_type="encoded_powershell_matches",
            host="DC01",
            minutes=30,
            limit=25,
        )
        spl = build_allowlisted_spl(req)
        self.assertTrue(spl.startswith("search index=main"))
        self.assertIn('host="DC01"', spl)
        self.assertIn('earliest="-30m"', spl)
        self.assertIn("<EventID>1</EventID>", spl)
        self.assertIn('rex field=_raw "<Data Name=[\'\\"]Image[\'\\"]>(?<Image>[^<]+)</Data>"', spl)
        self.assertIn('rex field=_raw "<Data Name=[\'\\"]CommandLine[\'\\"]>(?<CommandLine>[^<]+)</Data>"', spl)
        self.assertIn('rex field=_raw "<Data Name=[\'\\"]ParentImage[\'\\"]>(?<ParentImage>[^<]+)</Data>"', spl)
        self.assertIn('rex field=_raw "<Data Name=[\'\\"]ParentCommandLine[\'\\"]>(?<ParentCommandLine>[^<]+)</Data>"', spl)
        self.assertIn('rex field=_raw "<Data Name=[\'\\"]User[\'\\"]>(?<User>[^<]+)</Data>"', spl)
        self.assertIn('where match(Image, "(?i)powershell[.]exe$")', spl)
        self.assertIn('where match(CommandLine, "(?i)(^|[[:space:]])-(encodedcommand|enc)([[:space:]]|$)")', spl)
        self.assertIn("| sort - _time", spl)
        self.assertIn("| head 25", spl)
        self.assertIn("| table _time host User Image CommandLine ParentImage ParentCommandLine", spl)


class TestRawSysmonXmlExtraction(unittest.TestCase):
    """Regression tests proving raw Sysmon XML extraction and filtering semantics (Milestone 5B-2 fix)."""

    def setUp(self) -> None:
        import re
        self.re = re
        req = SearchRequest(
            query_type="encoded_powershell_matches",
            host="DC01",
            minutes=15,
            limit=10,
        )
        self.spl = build_allowlisted_spl(req)

    def _simulate_spl_pipeline(self, raw_xml: str, host: str = "DC01", time_val: str = "2026-09-15T12:00:00.000Z"):
        """Simulate Splunk pipeline execution (initial search term filter, rex extractions, and where filters)."""
        # 1. Base search filter: must contain <EventID>1</EventID>
        if "<EventID>1</EventID>" not in raw_xml:
            return None

        # 2. Extract rex patterns from SPL (matching until unescaped double quote)
        rex_matches = self.re.findall(r'rex field=_raw "(.*?)(?<!\\)"', self.spl)
        record = {"_time": time_val, "host": host}
        for rex_pat in rex_matches:
            unescaped_pat = rex_pat.replace(r'\"', '"')
            py_pat = self.re.sub(r'\(\?<([a-zA-Z0-9_]+)>', r'(?P<\1>', unescaped_pat)
            m = self.re.search(py_pat, raw_xml)
            if m:
                record.update(m.groupdict())

        # 3. Where clause filter: Image must match powershell[.]exe$
        where_img = self.re.search(r'where match\(Image,\s*"([^"]+)"\)', self.spl)
        if where_img:
            img_pat = where_img.group(1)
            img_val = record.get("Image", "")
            if not self.re.search(img_pat, img_val):
                return None

        # 4. Where clause filter: match(CommandLine, "(?i)(^|[[:space:]])-(encodedcommand|enc)([[:space:]]|$)")
        where_cmd = self.re.search(r'where match\(CommandLine,\s*"([^"]+)"\)', self.spl)
        if where_cmd:
            cmd_pat = where_cmd.group(1)
            # In Python re, translate POSIX [[:space:]] to \s
            py_cmd_pat = cmd_pat.replace("[[:space:]]", r"\s")
            cmd_val = record.get("CommandLine", "")
            if not self.re.search(py_cmd_pat, cmd_val):
                return None

        return record

    def test_powershell_with_encoded_command_matches(self) -> None:
        """Proof: powershell.exe + -EncodedCommand matches and extracts correctly."""
        raw_xml = (
            "<Event><System><EventID>1</EventID></System><EventData>"
            "<Data Name='Image'>C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe</Data>"
            "<Data Name='CommandLine'>powershell.exe -NoProfile -EncodedCommand VwByAGkAdABl...</Data>"
            "<Data Name='ParentImage'>C:\\Windows\\System32\\cmd.exe</Data>"
            "<Data Name='ParentCommandLine'>\"C:\\Windows\\system32\\cmd.exe\"</Data>"
            "<Data Name='User'>SOCLAB\\Administrator</Data>"
            "</EventData></Event>"
        )
        record = self._simulate_spl_pipeline(raw_xml)
        self.assertIsNotNone(record)
        self.assertTrue(record["Image"].endswith("powershell.exe"))
        self.assertIn("-EncodedCommand", record["CommandLine"])

    def test_powershell_with_enc_matches(self) -> None:
        """Proof: powershell.exe + -enc matches as a standalone token."""
        raw_xml = (
            "<Event><System><EventID>1</EventID></System><EventData>"
            "<Data Name='Image'>C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe</Data>"
            "<Data Name='CommandLine'>powershell.exe -enc VwByAGkAdABl...</Data>"
            "<Data Name='ParentImage'>C:\\Windows\\System32\\cmd.exe</Data>"
            "<Data Name='ParentCommandLine'>\"C:\\Windows\\system32\\cmd.exe\"</Data>"
            "<Data Name='User'>SOCLAB\\Administrator</Data>"
            "</EventData></Event>"
        )
        record = self._simulate_spl_pipeline(raw_xml)
        self.assertIsNotNone(record)
        self.assertIn("-enc", record["CommandLine"])

    def test_powershell_no_encoded_argument_rejected(self) -> None:
        """Proof: powershell.exe without encoded argument (-EncodedCommand or -enc) is rejected."""
        raw_xml = (
            "<Event><System><EventID>1</EventID></System><EventData>"
            "<Data Name='Image'>C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe</Data>"
            "<Data Name='CommandLine'>powershell.exe -NoProfile Write-Host 'Unencoded benign'</Data>"
            "<Data Name='ParentImage'>C:\\Windows\\System32\\cmd.exe</Data>"
            "<Data Name='ParentCommandLine'>\"C:\\Windows\\system32\\cmd.exe\"</Data>"
            "<Data Name='User'>SOCLAB\\Administrator</Data>"
            "</EventData></Event>"
        )
        record = self._simulate_spl_pipeline(raw_xml)
        self.assertIsNone(record)

    def test_cmd_exe_with_encoded_command_rejected(self) -> None:
        """Proof: Non-powershell Image (cmd.exe) containing -EncodedCommand is rejected."""
        raw_xml = (
            "<Event><System><EventID>1</EventID></System><EventData>"
            "<Data Name='Image'>C:\\Windows\\System32\\cmd.exe</Data>"
            "<Data Name='CommandLine'>cmd.exe /c echo -EncodedCommand</Data>"
            "<Data Name='ParentImage'>C:\\Windows\\explorer.exe</Data>"
            "<Data Name='ParentCommandLine'>\"C:\\Windows\\explorer.exe\"</Data>"
            "<Data Name='User'>SOCLAB\\Administrator</Data>"
            "</EventData></Event>"
        )
        record = self._simulate_spl_pipeline(raw_xml)
        self.assertIsNone(record)

    def test_another_executable_with_enc_rejected(self) -> None:
        """Proof: Another non-powershell executable (certutil.exe) containing -enc is rejected."""
        raw_xml = (
            "<Event><System><EventID>1</EventID></System><EventData>"
            "<Data Name='Image'>C:\\Windows\\System32\\certutil.exe</Data>"
            "<Data Name='CommandLine'>certutil.exe -enc payload.txt</Data>"
            "<Data Name='ParentImage'>C:\\Windows\\System32\\cmd.exe</Data>"
            "<Data Name='ParentCommandLine'>\"cmd.exe\"</Data>"
            "<Data Name='User'>SOCLAB\\Administrator</Data>"
            "</EventData></Event>"
        )
        record = self._simulate_spl_pipeline(raw_xml)
        self.assertIsNone(record)

    def test_encoding_or_encrypt_token_rejected(self) -> None:
        """Proof: Longer tokens like -encoding or -encrypt do not satisfy the -enc token match."""
        # Case A: -encoding
        raw_xml_encoding = (
            "<Event><System><EventID>1</EventID></System><EventData>"
            "<Data Name='Image'>C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe</Data>"
            "<Data Name='CommandLine'>powershell.exe -NoProfile -encoding utf8 script.ps1</Data>"
            "<Data Name='ParentImage'>C:\\Windows\\System32\\cmd.exe</Data>"
            "<Data Name='ParentCommandLine'>\"cmd.exe\"</Data>"
            "<Data Name='User'>SOCLAB\\Administrator</Data>"
            "</EventData></Event>"
        )
        self.assertIsNone(self._simulate_spl_pipeline(raw_xml_encoding))

        # Case B: -encrypt
        raw_xml_encrypt = (
            "<Event><System><EventID>1</EventID></System><EventData>"
            "<Data Name='Image'>C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe</Data>"
            "<Data Name='CommandLine'>powershell.exe -encrypt data.txt</Data>"
            "<Data Name='ParentImage'>C:\\Windows\\System32\\cmd.exe</Data>"
            "<Data Name='ParentCommandLine'>\"cmd.exe\"</Data>"
            "<Data Name='User'>SOCLAB\\Administrator</Data>"
            "</EventData></Event>"
        )
        self.assertIsNone(self._simulate_spl_pipeline(raw_xml_encrypt))

    def test_raw_sysmon_xml_single_quotes_extracted_correctly(self) -> None:
        """Proof: Raw Sysmon XML with single-quoted attributes produces expected fields without pre-extraction."""
        raw_xml = (
            "<Event><System><EventID>1</EventID></System><EventData>"
            "<Data Name='Image'>C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe</Data>"
            "<Data Name='CommandLine'>powershell.exe -NoProfile -EncodedCommand VwByAGkAdABlAC0ASABvAHMAdAA...</Data>"
            "<Data Name='ParentImage'>C:\\Windows\\System32\\cmd.exe</Data>"
            "<Data Name='ParentCommandLine'>\"C:\\Windows\\system32\\cmd.exe\"</Data>"
            "<Data Name='User'>SOCLAB\\Administrator</Data>"
            "</EventData></Event>"
        )
        record = self._simulate_spl_pipeline(raw_xml)
        self.assertIsNotNone(record)
        self.assertEqual(record["Image"], "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe")
        self.assertTrue(record["CommandLine"].startswith("powershell.exe -NoProfile -EncodedCommand"))
        self.assertEqual(record["ParentImage"], "C:\\Windows\\System32\\cmd.exe")
        self.assertEqual(record["ParentCommandLine"], '"C:\\Windows\\system32\\cmd.exe"')
        self.assertEqual(record["User"], "SOCLAB\\Administrator")
        self.assertEqual(record["host"], "DC01")

    def test_raw_sysmon_xml_double_quotes_extracted_correctly(self) -> None:
        """Proof: Raw Sysmon XML with double-quoted attributes produces expected fields identically."""
        raw_xml = (
            '<Event><System><EventID>1</EventID></System><EventData>'
            '<Data Name="Image">C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe</Data>'
            '<Data Name="CommandLine">powershell.exe -NoProfile -EncodedCommand VwByAGkAdABlAC0ASABvAHMAdAA...</Data>'
            '<Data Name="ParentImage">C:\\Windows\\System32\\cmd.exe</Data>'
            '<Data Name="ParentCommandLine">"C:\\Windows\\system32\\cmd.exe"</Data>'
            '<Data Name="User">SOCLAB\\Administrator</Data>'
            '</EventData></Event>'
        )
        record = self._simulate_spl_pipeline(raw_xml)
        self.assertIsNotNone(record)
        self.assertEqual(record["Image"], "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe")
        self.assertTrue(record["CommandLine"].startswith("powershell.exe -NoProfile -EncodedCommand"))
        self.assertEqual(record["ParentImage"], "C:\\Windows\\System32\\cmd.exe")
        self.assertEqual(record["ParentCommandLine"], '"C:\\Windows\\system32\\cmd.exe"')
        self.assertEqual(record["User"], "SOCLAB\\Administrator")

    def test_event_id_not_1_rejected(self) -> None:
        """Proof: EventID != 1 (e.g. Sysmon EventID 3 Network Connect) is rejected/not matched."""
        raw_xml = (
            "<Event><System><EventID>3</EventID></System><EventData>"
            "<Data Name='Image'>C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe</Data>"
            "<Data Name='CommandLine'>powershell.exe -NoProfile -EncodedCommand VwByAGkAdABl...</Data>"
            "<Data Name='ParentImage'>C:\\Windows\\System32\\cmd.exe</Data>"
            "<Data Name='ParentCommandLine'>\"C:\\Windows\\system32\\cmd.exe\"</Data>"
            "<Data Name='User'>SOCLAB\\Administrator</Data>"
            "</EventData></Event>"
        )
        record = self._simulate_spl_pipeline(raw_xml)
        self.assertIsNone(record)

    def test_all_contract_fields_present_and_non_empty(self) -> None:
        """Proof: Extracted records satisfy all 7 mandatory contract fields in ALLOWED_FIELDS."""
        raw_xml = (
            "<Event><System><EventID>1</EventID></System><EventData>"
            "<Data Name='Image'>C:\\Windows\\System32\\powershell.exe</Data>"
            "<Data Name='CommandLine'>powershell.exe -enc test</Data>"
            "<Data Name='ParentImage'>C:\\Windows\\System32\\cmd.exe</Data>"
            "<Data Name='ParentCommandLine'>\"cmd.exe\"</Data>"
            "<Data Name='User'>SOCLAB\\Administrator</Data>"
            "</EventData></Event>"
        )
        record = self._simulate_spl_pipeline(raw_xml)
        self.assertIsNotNone(record)
        for field in ALLOWED_FIELDS:
            self.assertIn(field, record)
            self.assertTrue(bool(str(record[field]).strip()))


if __name__ == "__main__":
    unittest.main()

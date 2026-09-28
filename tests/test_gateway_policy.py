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

    def test_powershell_network_retrieval_query_type_accepted(self) -> None:
        """Verify that 'powershell_network_retrieval_matches' is accepted as a valid query_type."""
        req = validate_search_request(
            query_type="powershell_network_retrieval_matches",
            host="DC01",
            minutes=15,
            limit=10,
        )
        self.assertIsInstance(req, SearchRequest)
        self.assertEqual(req.query_type, "powershell_network_retrieval_matches")
        self.assertEqual(req.host, "DC01")
        self.assertEqual(req.minutes, 15)
        self.assertEqual(req.limit, 10)

    def test_build_allowlisted_spl_powershell_network_retrieval(self) -> None:
        """Verify build_allowlisted_spl() constructs the expected SPL for powershell_network_retrieval_matches."""
        req = SearchRequest(
            query_type="powershell_network_retrieval_matches",
            host="DC01",
            minutes=20,
            limit=15,
        )
        spl = build_allowlisted_spl(req)
        self.assertTrue(spl.startswith("search index=main"))
        self.assertIn('sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational"', spl)
        self.assertIn('host="DC01"', spl)
        self.assertIn('earliest="-20m"', spl)
        self.assertIn("<EventID>1</EventID>", spl)
        self.assertIn('rex field=_raw "<Data Name=[\'\\"]Image[\'\\"]>(?<Image>[^<]+)</Data>"', spl)
        self.assertIn('rex field=_raw "<Data Name=[\'\\"]CommandLine[\'\\"]>(?<CommandLine>[^<]+)</Data>"', spl)
        self.assertIn('rex field=_raw "<Data Name=[\'\\"]ParentImage[\'\\"]>(?<ParentImage>[^<]+)</Data>"', spl)
        self.assertIn('rex field=_raw "<Data Name=[\'\\"]ParentCommandLine[\'\\"]>(?<ParentCommandLine>[^<]+)</Data>"', spl)
        self.assertIn('rex field=_raw "<Data Name=[\'\\"]User[\'\\"]>(?<User>[^<]+)</Data>"', spl)
        self.assertIn('where match(Image, "(?i)powershell[.]exe$")', spl)
        self.assertIn(
            'where match(CommandLine, "(?i)(Invoke-WebRequest|Invoke-RestMethod|[.]DownloadString\\()")',
            spl,
        )
        self.assertIn("| sort - _time", spl)
        self.assertIn("| head 15", spl)
        self.assertIn("| table _time host User Image CommandLine ParentImage ParentCommandLine", spl)

    def test_encoded_powershell_matches_predicate_preserved(self) -> None:
        """Verify encoded_powershell_matches still produces the existing encoded-command predicate."""
        req = SearchRequest(
            query_type="encoded_powershell_matches",
            host="DC01",
            minutes=15,
            limit=10,
        )
        spl = build_allowlisted_spl(req)
        self.assertIn('where match(CommandLine, "(?i)(^|[[:space:]])-(encodedcommand|enc)([[:space:]]|$)")', spl)
        self.assertNotIn("Invoke-WebRequest", spl)

    def test_unknown_query_type_rejected_with_new_allowed_type(self) -> None:
        """Verify an unknown or arbitrary query type is still rejected."""
        invalid_types = [
            "unknown_type",
            "powershell_retrieval",
            "encoded_powershell",
            "network_retrieval",
            "",
            "powershell_network_retrieval",
        ]
        for q_type in invalid_types:
            with self.subTest(query_type=q_type):
                with self.assertRaises(PolicyValidationError):
                    validate_search_request(
                        query_type=q_type,
                        host="DC01",
                        minutes=15,
                        limit=10,
                    )

    def test_arbitrary_query_text_injection_prevented_in_query_type(self) -> None:
        """Verify callers cannot inject arbitrary query text through query_type or other parameters."""
        malicious_inputs = [
            'encoded_powershell_matches | search *',
            'powershell_network_retrieval_matches" | delete',
            'encoded_powershell_matches; eval 1=1',
            '<EventID>1</EventID>',
            'index=other',
        ]
        for mal in malicious_inputs:
            with self.subTest(payload=mal):
                with self.assertRaises(PolicyValidationError):
                    validate_search_request(
                        query_type=mal,
                        host="DC01",
                        minutes=15,
                        limit=10,
                    )


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

    def test_encoded_argument_matching_is_case_insensitive(self) -> None:
        """Proof: Mixed-case flags such as -ENC and -eNcOdEdCoMmAnD are matched case-insensitively."""
        test_flags = ["-ENC", "-eNcOdEdCoMmAnD"]
        for flag in test_flags:
            with self.subTest(flag=flag):
                raw_xml = (
                    f"<Event><System><EventID>1</EventID></System><EventData>"
                    f"<Data Name='Image'>C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe</Data>"
                    f"<Data Name='CommandLine'>powershell.exe {flag} VwByAGkAdABl...</Data>"
                    f"<Data Name='ParentImage'>C:\\Windows\\System32\\cmd.exe</Data>"
                    f"<Data Name='ParentCommandLine'>\"cmd.exe\"</Data>"
                    f"<Data Name='User'>SOCLAB\\Administrator</Data>"
                    f"</EventData></Event>"
                )
                record = self._simulate_spl_pipeline(raw_xml)
                self.assertIsNotNone(record)

    def test_enc_prefix_inside_longer_token_rejected(self) -> None:
        """Proof: -enc prefix inside a longer unseparated token like -encfoo is rejected."""
        raw_xml = (
            "<Event><System><EventID>1</EventID></System><EventData>"
            "<Data Name='Image'>C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe</Data>"
            "<Data Name='CommandLine'>powershell.exe -encfoo AAAA</Data>"
            "<Data Name='ParentImage'>C:\\Windows\\System32\\cmd.exe</Data>"
            "<Data Name='ParentCommandLine'>\"cmd.exe\"</Data>"
            "<Data Name='User'>SOCLAB\\Administrator</Data>"
            "</EventData></Event>"
        )
        record = self._simulate_spl_pipeline(raw_xml)
        self.assertIsNone(record)

    def test_encodedcommand_prefix_inside_longer_token_rejected(self) -> None:
        """Proof: -EncodedCommand prefix inside a longer unseparated token like -EncodedCommandX is rejected."""
        raw_xml = (
            "<Event><System><EventID>1</EventID></System><EventData>"
            "<Data Name='Image'>C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe</Data>"
            "<Data Name='CommandLine'>powershell.exe -EncodedCommandX AAAA</Data>"
            "<Data Name='ParentImage'>C:\\Windows\\System32\\cmd.exe</Data>"
            "<Data Name='ParentCommandLine'>\"cmd.exe\"</Data>"
            "<Data Name='User'>SOCLAB\\Administrator</Data>"
            "</EventData></Event>"
        )
        record = self._simulate_spl_pipeline(raw_xml)
        self.assertIsNone(record)

    def test_encoded_argument_at_command_line_end_matches(self) -> None:
        """Proof: Encoded argument flag positioned at the end of the command line matches regex boundary."""
        raw_xml = (
            "<Event><System><EventID>1</EventID></System><EventData>"
            "<Data Name='Image'>C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe</Data>"
            "<Data Name='CommandLine'>powershell.exe -enc</Data>"
            "<Data Name='ParentImage'>C:\\Windows\\System32\\cmd.exe</Data>"
            "<Data Name='ParentCommandLine'>\"cmd.exe\"</Data>"
            "<Data Name='User'>SOCLAB\\Administrator</Data>"
            "</EventData></Event>"
        )
        record = self._simulate_spl_pipeline(raw_xml)
        self.assertIsNotNone(record)


class TestPowerShellNetworkRetrievalDetection(unittest.TestCase):
    """Regression test suite for Suspicious PowerShell Network Retrieval detection artifact.

    Validates the detection logic defined in:
    detections/splunk/suspicious_powershell_network_retrieval.spl

    Known limitation note:
    The rule is string/regex based and does not parse PowerShell syntax, so quoted text
    containing "Invoke-WebRequest" may still match.
    """

    def setUp(self) -> None:
        import re
        from pathlib import Path

        self.re = re
        spl_path = (
            Path(__file__).resolve().parent.parent
            / "detections"
            / "splunk"
            / "suspicious_powershell_network_retrieval.spl"
        )
        with open(spl_path, "r", encoding="utf-8") as f:
            self.spl = f.read()

    def _simulate_network_retrieval_spl(
        self,
        raw_xml: str,
        host: str = "DC01",
        time_val: str = "2026-09-28T12:00:00.000Z",
    ):
        """Simulate Splunk pipeline execution derived directly from the SPL artifact.

        Pipeline steps extracted from self.spl:
        1. Base filter: EventID 1 condition
        2. Field extraction: rex field=_raw patterns
        3. Image filter: match(Image, ...) regex
        4. CommandLine filter: match(CommandLine, ...) regex
        """
        # 1. Base search filter: verify both SPL and raw_xml contain <EventID>1</EventID>
        if "<EventID>1</EventID>" not in self.spl:
            return None
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

        # 3. Where clause filter: Image
        where_img = self.re.search(r'where match\(Image,\s*"([^"]+)"\)', self.spl)
        if where_img:
            img_pat = where_img.group(1)
            img_val = record.get("Image", "")
            if not self.re.search(img_pat, img_val):
                return None

        # 4. Where clause filter: CommandLine
        where_cmd = self.re.search(r'where match\(CommandLine,\s*"([^"]+)"\)', self.spl)
        if where_cmd:
            cmd_pat = where_cmd.group(1)
            py_cmd_pat = cmd_pat.replace("[[:space:]]", r"\s")
            cmd_val = record.get("CommandLine", "")
            if not self.re.search(py_cmd_pat, cmd_val):
                return None

        return record

    def test_invoke_webrequest_matches(self) -> None:
        """Proof: powershell.exe invoking Invoke-WebRequest matches."""
        raw_xml = (
            "<Event><System><EventID>1</EventID></System><EventData>"
            "<Data Name='Image'>C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe</Data>"
            "<Data Name='CommandLine'>powershell.exe -NoProfile -Command \"Invoke-WebRequest -Uri http://127.0.0.1/test\"</Data>"
            "<Data Name='ParentImage'>C:\\Windows\\System32\\cmd.exe</Data>"
            "<Data Name='ParentCommandLine'>\"cmd.exe\"</Data>"
            "<Data Name='User'>SOCLAB\\Administrator</Data>"
            "</EventData></Event>"
        )
        record = self._simulate_network_retrieval_spl(raw_xml)
        self.assertIsNotNone(record)
        self.assertIn("Invoke-WebRequest", record["CommandLine"])

    def test_invoke_restmethod_matches(self) -> None:
        """Proof: powershell.exe invoking Invoke-RestMethod matches."""
        raw_xml = (
            "<Event><System><EventID>1</EventID></System><EventData>"
            "<Data Name='Image'>C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe</Data>"
            "<Data Name='CommandLine'>powershell.exe -NoProfile -Command \"Invoke-RestMethod -Uri http://127.0.0.1/test\"</Data>"
            "<Data Name='ParentImage'>C:\\Windows\\System32\\cmd.exe</Data>"
            "<Data Name='ParentCommandLine'>\"cmd.exe\"</Data>"
            "<Data Name='User'>SOCLAB\\Administrator</Data>"
            "</EventData></Event>"
        )
        record = self._simulate_network_retrieval_spl(raw_xml)
        self.assertIsNotNone(record)
        self.assertIn("Invoke-RestMethod", record["CommandLine"])

    def test_downloadstring_matches(self) -> None:
        """Proof: powershell.exe invoking .DownloadString( matches."""
        raw_xml = (
            "<Event><System><EventID>1</EventID></System><EventData>"
            "<Data Name='Image'>C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe</Data>"
            "<Data Name='CommandLine'>powershell.exe -NoProfile -Command \"(New-Object Net.WebClient).DownloadString('http://127.0.0.1/test')\"</Data>"
            "<Data Name='ParentImage'>C:\\Windows\\System32\\cmd.exe</Data>"
            "<Data Name='ParentCommandLine'>\"cmd.exe\"</Data>"
            "<Data Name='User'>SOCLAB\\Administrator</Data>"
            "</EventData></Event>"
        )
        record = self._simulate_network_retrieval_spl(raw_xml)
        self.assertIsNotNone(record)
        self.assertIn(".DownloadString(", record["CommandLine"])

    def test_network_retrieval_matching_is_case_insensitive(self) -> None:
        """Proof: Lowercase or mixed-case indicator like invoke-webrequest matches case-insensitively."""
        raw_xml = (
            "<Event><System><EventID>1</EventID></System><EventData>"
            "<Data Name='Image'>C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe</Data>"
            "<Data Name='CommandLine'>powershell.exe -NoProfile -Command \"invoke-webrequest -Uri http://127.0.0.1/test\"</Data>"
            "<Data Name='ParentImage'>C:\\Windows\\System32\\cmd.exe</Data>"
            "<Data Name='ParentCommandLine'>\"cmd.exe\"</Data>"
            "<Data Name='User'>SOCLAB\\Administrator</Data>"
            "</EventData></Event>"
        )
        record = self._simulate_network_retrieval_spl(raw_xml)
        self.assertIsNotNone(record)

    def test_normal_powershell_command_rejected(self) -> None:
        """Proof: Normal PowerShell execution without retrieval primitives is rejected."""
        raw_xml = (
            "<Event><System><EventID>1</EventID></System><EventData>"
            "<Data Name='Image'>C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe</Data>"
            "<Data Name='CommandLine'>powershell.exe -NoProfile -Command \"Write-Host 'hello'\"</Data>"
            "<Data Name='ParentImage'>C:\\Windows\\System32\\cmd.exe</Data>"
            "<Data Name='ParentCommandLine'>\"cmd.exe\"</Data>"
            "<Data Name='User'>SOCLAB\\Administrator</Data>"
            "</EventData></Event>"
        )
        record = self._simulate_network_retrieval_spl(raw_xml)
        self.assertIsNone(record)

    def test_non_powershell_process_with_indicator_rejected(self) -> None:
        """Proof: Non-powershell Image (cmd.exe) containing retrieval indicator is rejected."""
        raw_xml = (
            "<Event><System><EventID>1</EventID></System><EventData>"
            "<Data Name='Image'>C:\\Windows\\System32\\cmd.exe</Data>"
            "<Data Name='CommandLine'>cmd.exe /c echo Invoke-WebRequest</Data>"
            "<Data Name='ParentImage'>C:\\Windows\\explorer.exe</Data>"
            "<Data Name='ParentCommandLine'>\"C:\\Windows\\explorer.exe\"</Data>"
            "<Data Name='User'>SOCLAB\\Administrator</Data>"
            "</EventData></Event>"
        )
        record = self._simulate_network_retrieval_spl(raw_xml)
        self.assertIsNone(record)


if __name__ == "__main__":
    unittest.main()

"""Unit tests for Milestone 18B-1: Scheduled Task Detection Plane (DET-TASK-001).

Validates:
- Detection regex / path boundary / token-boundary logic (positive, case-insensitive, negative, boundaries)
- SPL rule structure and syntax
- Sigma rule structure, semantic alignment, and portable regex modifier
- Gateway policy allowlist, bounded query safety, and DC01-only host coupling
- SplunkSearchClient typed helper search_scheduled_task_creation
- Static deterministic MITRE mapping to T1053.005
- Regression safety for existing DET-POWERSHELL-001, DET-POWERSHELL-002, and WEB01 ModSecurity
"""

import os
import re
import unittest
from unittest.mock import MagicMock, patch

from gateway.policy import (
    ALLOWED_FIELDS,
    ALLOWED_HOSTS,
    ALLOWED_QUERY_TYPES,
    PolicyValidationError,
    SearchRequest,
    build_allowlisted_spl,
    validate_search_request,
)
from gateway.splunk_search import (
    SPLUNK_EXPORT_ENDPOINT,
    SplunkSearchClient,
)
from investigator.tools.mitre_mapper import (
    MitreMapping,
    MitreMappingError,
    map_detection_to_mitre,
)

# SPL predicate string defined in gateway policy and detections/splunk/suspicious_scheduled_task_creation.spl
SPL_IMAGE_PREDICATE = r"(?i)(^|.*[\\\\/])schtasks[.]exe$"
SPL_COMMANDLINE_PREDICATE = r"(?i)(^|[[:space:]])/create([[:space:]]|$)"

# Python re does not support POSIX [[:space:]] syntax native to PCRE (Splunk match());
# translate [[:space:]] to \s to validate the exact semantics offline.
IMAGE_REGEX = re.compile(SPL_IMAGE_PREDICATE)
COMMANDLINE_REGEX = re.compile(SPL_COMMANDLINE_PREDICATE.replace("[[:space:]]", r"\s"))


class TestScheduledTaskDetectionLogic(unittest.TestCase):
    """Test regex matching, path boundary, and token boundary semantics for DET-TASK-001."""

    def test_positive_detection(self) -> None:
        """A. Positive detection: Image ends with schtasks.exe and CommandLine contains /create token."""
        image = r"C:\Windows\System32\schtasks.exe"
        cmdline = r'schtasks.exe /create /tn "PersistenceTask" /tr "C:\evil.exe" /sc onstart'

        self.assertIsNotNone(IMAGE_REGEX.search(image))
        self.assertIsNotNone(COMMANDLINE_REGEX.search(cmdline))

    def test_case_insensitive_positive(self) -> None:
        """B. Case-insensitive positive: SCHTASKS.EXE and /CREATE match."""
        image = r"C:\WINDOWS\SYSTEM32\SCHTASKS.EXE"
        cmdline = r'SCHTASKS.EXE /CREATE /TN "BACKDOOR" /TR "CALC.EXE" /SC DAILY'

        self.assertIsNotNone(IMAGE_REGEX.search(image))
        self.assertIsNotNone(COMMANDLINE_REGEX.search(cmdline))

    def test_exact_live_dc01_windows_path_matches(self) -> None:
        """10. Regression: prove the exact live Windows DC01 path matches operational regex semantics."""
        live_dc01_path = r"C:\Windows\System32\schtasks.exe"
        self.assertIsNotNone(IMAGE_REGEX.search(live_dc01_path))

    def test_positive_image_path_boundary_variants(self) -> None:
        """Verify positive matching for various valid schtasks.exe executable paths."""
        valid_images = [
            "schtasks.exe",
            r"C:\Windows\System32\schtasks.exe",
            "C:/Windows/System32/schtasks.exe",
            r"c:\windows\system32\schtasks.exe",
            "SCHTASKS.EXE",
            r"C:\WINDOWS\SYSTEM32\SCHTASKS.EXE",
        ]
        for img in valid_images:
            with self.subTest(image=img):
                self.assertIsNotNone(IMAGE_REGEX.search(img))

    def test_negative_image_path_boundary_rejections(self) -> None:
        """Verify strict path boundary rejects fake or prefix-spoofed executable names."""
        rejected_images = [
            "fakeschtasks.exe",
            "myschtasks.exe",
            r"C:\Temp\fakeschtasks.exe",
            r"C:\Temp\evil-schtasks.exe",
            r"C:\Windows\Temp\evil_schtasks.exe",
            "schtasks.exe.bak",
            "schtasks.exe1",
            r"C:\schtasks.exe.other",
        ]
        for img in rejected_images:
            with self.subTest(image=img):
                self.assertIsNone(IMAGE_REGEX.search(img))

    def test_negative_query_operation_only(self) -> None:
        """C. Negative: schtasks.exe /query must not match."""
        image = r"C:\Windows\System32\schtasks.exe"
        cmdline = r"schtasks.exe /query /fo LIST /v"

        self.assertIsNotNone(IMAGE_REGEX.search(image))
        self.assertIsNone(COMMANDLINE_REGEX.search(cmdline))

    def test_negative_delete_operation(self) -> None:
        """D. Negative: schtasks.exe /delete must not match."""
        image = r"C:\Windows\System32\schtasks.exe"
        cmdline = r'schtasks.exe /delete /tn "CleanupTask" /f'

        self.assertIsNotNone(IMAGE_REGEX.search(image))
        self.assertIsNone(COMMANDLINE_REGEX.search(cmdline))

    def test_negative_unrelated_executable(self) -> None:
        """E. Negative: cmd.exe with text mentioning schtasks /create must not match."""
        image = r"C:\Windows\System32\cmd.exe"
        cmdline = r'cmd.exe /c schtasks /create /tn "Test" /tr "notepad.exe"'

        self.assertIsNone(IMAGE_REGEX.search(image))
        self.assertIsNotNone(COMMANDLINE_REGEX.search(cmdline))

    def test_negative_token_boundary_behavior(self) -> None:
        """F. Token-boundary behavior: malformed substrings (/created, /createXYZ) must not match."""
        image = r"C:\Windows\System32\schtasks.exe"
        malformed_commands = [
            r'schtasks.exe /created /tn "Test"',
            r'schtasks.exe /createXYZ /tn "Test"',
            r'schtasks.exe /create_task /tn "Test"',
            r'schtasks.exe /recreate /tn "Test"',
            r'schtasks.exe /createsomething /tn "Test"',
        ]

        self.assertIsNotNone(IMAGE_REGEX.search(image))
        for cmdline in malformed_commands:
            with self.subTest(cmdline=cmdline):
                self.assertIsNone(COMMANDLINE_REGEX.search(cmdline))

    def test_valid_token_spacing_variations(self) -> None:
        """Verify token boundary matches at string boundaries and with various whitespace."""
        valid_variations = [
            r"schtasks.exe /create",
            r"/create /tn MyTask",
            r"schtasks.exe    /create    /tn MyTask",
            "schtasks.exe\t/create\t/tn MyTask",
            r'C:\Windows\System32\schtasks.exe /CREATE /TN "Task1"',
        ]
        for cmdline in valid_variations:
            with self.subTest(cmdline=cmdline):
                self.assertIsNotNone(COMMANDLINE_REGEX.search(cmdline))


class TestScheduledTaskSPLRuleFile(unittest.TestCase):
    """Test the authoritative SPL rule file content on disk."""

    def setUp(self) -> None:
        spl_path = os.path.join(
            os.path.dirname(os.path.dirname(__file__)),
            "detections",
            "splunk",
            "suspicious_scheduled_task_creation.spl",
        )
        with open(spl_path, "r", encoding="utf-8") as f:
            self.spl_content = f.read()

    def test_spl_file_syntax_and_elements(self) -> None:
        """Verify all mandatory elements in suspicious_scheduled_task_creation.spl."""
        self.assertIn("index=main", self.spl_content)
        self.assertIn('sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational"', self.spl_content)
        self.assertIn("<EventID>1</EventID>", self.spl_content)
        self.assertIn('rex field=_raw "<Data Name=[\'\\"]Image[\'\\"]>(?<Image>[^<]+)</Data>"', self.spl_content)
        self.assertIn('rex field=_raw "<Data Name=[\'\\"]CommandLine[\'\\"]>(?<CommandLine>[^<]+)</Data>"', self.spl_content)
        self.assertIn('rex field=_raw "<Data Name=[\'\\"]ParentImage[\'\\"]>(?<ParentImage>[^<]+)</Data>"', self.spl_content)
        self.assertIn('rex field=_raw "<Data Name=[\'\\"]ParentCommandLine[\'\\"]>(?<ParentCommandLine>[^<]+)</Data>"', self.spl_content)
        self.assertIn('rex field=_raw "<Data Name=[\'\\"]User[\'\\"]>(?<User>[^<]+)</Data>"', self.spl_content)
        self.assertIn(r'where match(Image, "(?i)(^|.*[\\\\/])schtasks[.]exe$")', self.spl_content)
        self.assertIn('where match(CommandLine, "(?i)(^|[[:space:]])/create([[:space:]]|$)")', self.spl_content)
        self.assertIn("table _time host User Image CommandLine ParentImage ParentCommandLine", self.spl_content)


class TestScheduledTaskSigmaRuleFile(unittest.TestCase):
    """Test the portable Sigma rule file content on disk."""

    def setUp(self) -> None:
        sigma_path = os.path.join(
            os.path.dirname(os.path.dirname(__file__)),
            "detections",
            "sigma",
            "suspicious_scheduled_task_creation.yml",
        )
        with open(sigma_path, "r", encoding="utf-8") as f:
            self.sigma_content = f.read()

    def test_sigma_file_structure_and_tags(self) -> None:
        """Verify Sigma rule mandatory fields, regex modifier, and ATT&CK tags."""
        self.assertIn("title: Suspicious Scheduled Task Creation", self.sigma_content)
        self.assertIn("id: c09a06ee-2216-43b5-bc5c-9c04da59434e", self.sigma_content)
        self.assertIn("category: process_creation", self.sigma_content)
        self.assertIn("product: windows", self.sigma_content)
        self.assertIn(r"Image|endswith:", self.sigma_content)
        self.assertIn(r"'\schtasks.exe'", self.sigma_content)
        self.assertIn(r"CommandLine|re:", self.sigma_content)
        self.assertIn(r"attack.persistence", self.sigma_content)
        self.assertIn(r"attack.t1053.005", self.sigma_content)
        self.assertNotIn("attack.privilege_escalation", self.sigma_content)


class TestScheduledTaskGatewaySupport(unittest.TestCase):
    """G & H: Test bounded Splunk gateway policy support and safety invariants."""

    def test_scheduled_task_query_type_accepted(self) -> None:
        """G. Gateway allowlist: scheduled_task_creation_matches is accepted as valid query_type for DC01."""
        req = validate_search_request(
            query_type="scheduled_task_creation_matches",
            host="DC01",
            minutes=15,
            limit=10,
        )
        self.assertIsInstance(req, SearchRequest)
        self.assertEqual(req.query_type, "scheduled_task_creation_matches")
        self.assertEqual(req.host, "DC01")
        self.assertEqual(req.minutes, 15)
        self.assertEqual(req.limit, 10)

    def test_scheduled_task_query_type_host_coupling_rejected_web01(self) -> None:
        """3. Host coupling: scheduled_task_creation_matches + web01 fails closed."""
        with self.assertRaises(PolicyValidationError) as ctx:
            validate_search_request(
                query_type="scheduled_task_creation_matches",
                host="web01",
                minutes=15,
                limit=10,
            )
        self.assertIn("Unauthorized host 'web01' for query_type 'scheduled_task_creation_matches'", str(ctx.exception))

    def test_direct_instantiation_rejects_scheduled_task_on_web01(self) -> None:
        """3. Direct SearchRequest instantiation rejects scheduled_task_creation_matches on web01."""
        with self.assertRaises(PolicyValidationError):
            SearchRequest(
                query_type="scheduled_task_creation_matches",
                host="web01",
                minutes=15,
                limit=10,
            )

    def test_builder_defense_in_depth_rejects_scheduled_task_on_web01(self) -> None:
        """3. build_allowlisted_spl rejects scheduled_task_creation_matches on web01 even if mutated."""
        req = SearchRequest(
            query_type="scheduled_task_creation_matches",
            host="DC01",
            minutes=15,
            limit=10,
        )
        object.__setattr__(req, "host", "web01")
        with self.assertRaises(PolicyValidationError):
            build_allowlisted_spl(req)

    def test_arbitrary_or_unrecognized_query_type_rejected(self) -> None:
        """G. Gateway allowlist: arbitrary/unrecognized query types fail closed."""
        invalid_types = [
            "scheduled_task_creation",
            "schtasks_matches",
            "scheduled_tasks",
            "arbitrary_spl",
            "",
            "encoded_powershell",
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

    def test_build_allowlisted_spl_scheduled_task(self) -> None:
        """Verify SPL builder produces exact bounded query with tightened Image predicate."""
        req = SearchRequest(
            query_type="scheduled_task_creation_matches",
            host="DC01",
            minutes=25,
            limit=20,
        )
        spl = build_allowlisted_spl(req)
        self.assertTrue(spl.startswith("search index=main"))
        self.assertIn('sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational"', spl)
        self.assertIn('host="DC01"', spl)
        self.assertIn('earliest="-25m"', spl)
        self.assertIn("<EventID>1</EventID>", spl)
        self.assertIn(r'where match(Image, "(?i)(^|.*[\\\\/])schtasks[.]exe$")', spl)
        self.assertIn('where match(CommandLine, "(?i)(^|[[:space:]])/create([[:space:]]|$)")', spl)
        self.assertIn("| sort - _time", spl)
        self.assertIn("| head 20", spl)
        self.assertIn("| table _time host User Image CommandLine ParentImage ParentCommandLine", spl)

    def test_bounded_query_safety_injections_prevented(self) -> None:
        """H. Bounded query safety: caller cannot inject raw SPL or violate boundaries."""
        malicious_inputs = [
            'scheduled_task_creation_matches | search *',
            'scheduled_task_creation_matches" | delete',
            'scheduled_task_creation_matches; eval 1=1',
            '<EventID>1</EventID>',
            'index=other',
        ]
        for bad in malicious_inputs:
            with self.subTest(input=bad):
                with self.assertRaises(PolicyValidationError):
                    validate_search_request(
                        query_type=bad,
                        host="DC01",
                        minutes=15,
                        limit=10,
                    )

    def test_bounded_query_safety_minutes_and_limit_bounds(self) -> None:
        """H. Bounded query safety: time window and limit parameters strictly bounded."""
        # Minutes out of bounds
        with self.assertRaises(PolicyValidationError):
            validate_search_request(
                query_type="scheduled_task_creation_matches",
                host="DC01",
                minutes=0,
                limit=10,
            )
        with self.assertRaises(PolicyValidationError):
            validate_search_request(
                query_type="scheduled_task_creation_matches",
                host="DC01",
                minutes=61,
                limit=10,
            )

        # Limit out of bounds
        with self.assertRaises(PolicyValidationError):
            validate_search_request(
                query_type="scheduled_task_creation_matches",
                host="DC01",
                minutes=15,
                limit=0,
            )
        with self.assertRaises(PolicyValidationError):
            validate_search_request(
                query_type="scheduled_task_creation_matches",
                host="DC01",
                minutes=15,
                limit=51,
            )

        # Unallowlisted host
        with self.assertRaises(PolicyValidationError):
            validate_search_request(
                query_type="scheduled_task_creation_matches",
                host="WORKSTATION1",
                minutes=15,
                limit=10,
            )


class TestScheduledTaskTypedSearchHelper(unittest.TestCase):
    """Test SplunkSearchClient.search_scheduled_task_creation helper."""

    def setUp(self) -> None:
        self.client = SplunkSearchClient(verify_tls=False, timeout=10.0)

    def _create_mock_response(self, content_str: str) -> MagicMock:
        mock_resp = MagicMock()
        mock_resp.read.side_effect = (
            lambda size=-1: content_str.encode("utf-8")[:size] if size != -1 else content_str.encode("utf-8")
        )
        mock_resp.__enter__.return_value = mock_resp
        mock_resp.__exit__.return_value = None
        return mock_resp

    def test_search_scheduled_task_creation_success(self) -> None:
        """Verify successful search dispatch and 7 allowlisted fields parsing."""
        mock_export_stream = (
            '{"preview":false,"offset":0,"lastrow":true,"result":{'
            '"_time":"2026-10-15T12:00:00.000+00:00",'
            '"host":"DC01",'
            '"User":"SOCLAB\\\\Administrator",'
            '"Image":"C:\\\\Windows\\\\System32\\\\schtasks.exe",'
            '"CommandLine":"schtasks.exe /create /tn EvilTask /tr C:\\\\evil.exe /sc onstart",'
            '"ParentImage":"C:\\\\Windows\\\\System32\\\\cmd.exe",'
            '"ParentCommandLine":"\\"cmd.exe\\"",'
            '"unrelated_field":"ignored"'
            '}}\n'
        )

        with patch("urllib.request.urlopen") as mock_urlopen:
            mock_urlopen.return_value = self._create_mock_response(mock_export_stream)

            results = self.client.search_scheduled_task_creation(
                host="DC01",
                minutes=15,
                limit=10,
            )

            mock_urlopen.assert_called_once()
            called_req = mock_urlopen.call_args[0][0]
            self.assertEqual(called_req.full_url, SPLUNK_EXPORT_ENDPOINT)
            self.assertEqual(called_req.get_method(), "POST")

            self.assertEqual(len(results), 1)
            event = results[0]
            self.assertEqual(event["host"], "DC01")
            self.assertEqual(event["User"], "SOCLAB\\Administrator")
            self.assertEqual(event["Image"], "C:\\Windows\\System32\\schtasks.exe")
            self.assertIn("/create", event["CommandLine"])
            self.assertEqual(event["ParentImage"], "C:\\Windows\\System32\\cmd.exe")
            self.assertEqual(event["ParentCommandLine"], '"cmd.exe"')
            self.assertNotIn("unrelated_field", event)


class TestScheduledTaskMitreMapping(unittest.TestCase):
    """I. Test deterministic MITRE ATT&CK mapping for DET-TASK-001."""

    def test_det_task_001_maps_exactly_to_t1053_005(self) -> None:
        """DET-TASK-001 and associated keys map to T1053.005."""
        refs = [
            "DET-TASK-001",
            "det-task-001",
            "Det-Task-001",
            "Suspicious Scheduled Task Creation",
            "suspicious_scheduled_task_creation",
            "scheduled_task_creation_matches",
            "c09a06ee-2216-43b5-bc5c-9c04da59434e",
        ]
        for ref in refs:
            with self.subTest(ref=ref):
                mapping = map_detection_to_mitre(ref)
                self.assertIsInstance(mapping, MitreMapping)
                self.assertTrue(mapping.mapped)
                self.assertEqual(mapping.technique_id, "T1053.005")
                self.assertEqual(mapping.technique_name, "Scheduled Task/Job: Scheduled Task")
                self.assertEqual(mapping.tactic_id, "TA0003")
                self.assertEqual(mapping.tactic_name, "Persistence")

    def test_unknown_detection_fails_closed(self) -> None:
        """Unknown detection still fails closed with MitreMappingError when fail_closed=True."""
        with self.assertRaises(MitreMappingError):
            map_detection_to_mitre("unknown_scheduled_task_rule", fail_closed=True)

        mapping = map_detection_to_mitre("unknown_scheduled_task_rule", fail_closed=False)
        self.assertFalse(mapping.mapped)
        self.assertIsNone(mapping.technique_id)
        self.assertIsNone(mapping.tactic_id)


class TestDetectionPlaneRegressions(unittest.TestCase):
    """J. Regression tests: existing DET-POWERSHELL-001, DET-POWERSHELL-002, and WEB01 remain unchanged."""

    def test_encoded_powershell_query_remains_unchanged(self) -> None:
        """Verify encoded_powershell_matches SPL construction is exactly preserved."""
        req = SearchRequest(
            query_type="encoded_powershell_matches",
            host="DC01",
            minutes=15,
            limit=10,
        )
        spl = build_allowlisted_spl(req)
        self.assertIn('where match(Image, "(?i)powershell[.]exe$")', spl)
        self.assertIn('where match(CommandLine, "(?i)(^|[[:space:]])-(encodedcommand|enc)([[:space:]]|$)")', spl)
        self.assertNotIn("schtasks", spl)

    def test_powershell_network_retrieval_query_remains_unchanged(self) -> None:
        """Verify powershell_network_retrieval_matches SPL construction is exactly preserved."""
        req = SearchRequest(
            query_type="powershell_network_retrieval_matches",
            host="DC01",
            minutes=15,
            limit=10,
        )
        spl = build_allowlisted_spl(req)
        self.assertIn('where match(Image, "(?i)powershell[.]exe$")', spl)
        self.assertIn('where match(CommandLine, "(?i)(Invoke-WebRequest|Invoke-RestMethod|[.]DownloadString\\()")', spl)
        self.assertNotIn("schtasks", spl)

    def test_existing_mitre_mappings_remain_unchanged(self) -> None:
        """Verify existing MITRE mappings remain intact."""
        ps1 = map_detection_to_mitre("encoded_powershell_matches")
        self.assertEqual(ps1.technique_id, "T1059.001")

        ps2 = map_detection_to_mitre("powershell_network_retrieval_matches")
        self.assertEqual(ps2.technique_id, "T1105")

    def test_existing_web01_modsecurity_query_accepted(self) -> None:
        """Verify existing valid WEB01 ModSecurity query remains accepted."""
        req = validate_search_request(
            query_type="modsecurity_sqli_matches",
            host="web01",
            minutes=15,
            limit=10,
        )
        self.assertEqual(req.host, "web01")
        self.assertEqual(req.query_type, "modsecurity_sqli_matches")
        spl = build_allowlisted_spl(req)
        self.assertIn('sourcetype=modsecurity host="web01"', spl)

    def test_existing_dc01_powershell_queries_accepted(self) -> None:
        """Verify existing DC01 PowerShell queries remain accepted."""
        req1 = validate_search_request(
            query_type="encoded_powershell_matches",
            host="DC01",
            minutes=15,
            limit=10,
        )
        self.assertEqual(req1.host, "DC01")
        req2 = validate_search_request(
            query_type="powershell_network_retrieval_matches",
            host="DC01",
            minutes=15,
            limit=10,
        )
        self.assertEqual(req2.host, "DC01")


if __name__ == "__main__":
    unittest.main()

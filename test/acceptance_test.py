import copy
import datetime as dt
import json
import unittest
from unittest.mock import Mock, call, patch

from acceptance import UTC, Run, ObserveRun, check_host, eligible


class AcceptanceGuards(unittest.TestCase):
    def setUp(self):
        self.now = dt.datetime(2026, 11, 2, tzinfo=UTC)
        self.pin = dict(hostname="canary",kernel="6.8.0-136-generic", version=2, module="pinned", tainted=45056, ring=1)
        self.host = dict(hostname="canary", ring=1, last_seen=self.now.isoformat(),
                         status=dict(kernel=self.pin["kernel"], version=2, tainted=45056,
                                     loaded=[dict(name="pinned", enabled=True, transition=False)]))

    def test_version_claim_does_not_prove_application(self):
        check_host(self.host, self.pin, self.now)
        for loaded in [[], [dict(name="pinned", enabled=False, transition=False)],
                       [dict(name="pinned", enabled=True, transition=True)],
                       [dict(name="foreign", enabled=True, transition=False)]]:
            with self.subTest(loaded=loaded):
                host = copy.deepcopy(self.host)
                host["status"]["loaded"] = loaded
                with self.assertRaises(ValueError):
                    check_host(host, self.pin, self.now)

    def test_stale_future_and_new_taint_fail_closed(self):
        for age in [121, -31]:
            host = copy.deepcopy(self.host)
            host["last_seen"] = (self.now-dt.timedelta(seconds=age)).isoformat()
            with self.assertRaises(ValueError):
                check_host(host, self.pin, self.now)
        self.host["status"]["tainted"] |= 512  # kernel WARN, not expected module taints
        with self.assertRaises(ValueError):
            check_host(self.host, self.pin, self.now)

    def test_policy_changes_fail_closed(self):
        for field, value in [("ring", 2), ("cordoned", True), ("reboot_request_id", 9)]:
            host = copy.deepcopy(self.host)
            host[field] = value
            with self.assertRaises(ValueError):
                check_host(host, self.pin, self.now)

    def test_existing_override_must_match_the_fixed_release_and_stay_unchanged(self):
        expected = dict(self.pin, update_now_kernel=self.pin["kernel"], update_now_version=2)
        host = copy.deepcopy(self.host)
        host.update(update_now_kernel=self.pin["kernel"], update_now_version=2)
        check_host(host, expected, self.now)
        for change in ({"update_now_version": 3}, {"update_now_version": 0}, {"update_now_kernel": "other"}):
            with self.subTest(change=change), self.assertRaises(ValueError):
                check_host(dict(host, **change), expected, self.now)
        with self.assertRaises(ValueError):
            check_host(dict(host, update_now_version=3), dict(expected, update_now_version=3), self.now)

    def test_lower_settings_cannot_shorten_24_hours(self):
        start = self.now.isoformat()
        self.assertFalse(eligible(start, self.now+dt.timedelta(seconds=86399), 0))
        self.assertTrue(eligible(start, self.now+dt.timedelta(days=1), 1440))
        self.assertFalse(eligible(start, self.now+dt.timedelta(days=1), 2880))

    def test_interrupted_deployment_cannot_replay_mutations(self):
        run = Run.__new__(Run)
        run.api = Mock()
        for phase in ["promoting", "rollback_test", "failed"]:
            run.state = {"phase": phase}
            with self.assertRaises(ValueError):
                run.run()
            run.api.assert_not_called()

    def test_restore_is_requested_even_if_rollback_observation_fails(self):
        run = Run.__new__(Run)
        run.manifest = {"hosts": []}
        run.action = Mock()
        run.node_checks = Mock()
        run.wait_applied = Mock(side_effect=RuntimeError("host did not settle"))
        with self.assertRaises(RuntimeError):
            run.rollback_one({"kernel": "test", "version": 2})
        self.assertEqual(run.action.call_args_list, [call("/api/kernels/test/rollback", {"version": 0}),
                                                     call("/api/kernels/test/rollback", {"version": 2})])

    def test_stop_during_rollback_still_requests_restoration(self):
        run = Run.__new__(Run)
        run.manifest = {"hosts": []}
        run.action = Mock()
        run.node_checks = Mock()
        run.wait_applied = Mock(side_effect=KeyboardInterrupt())
        with self.assertRaises(KeyboardInterrupt):
            run.rollback_one({"kernel": "test", "version": 2})
        self.assertEqual(run.action.call_args_list[-1], call("/api/kernels/test/rollback", {"version": 2}))

    def test_fresh_start_always_initializes_the_full_window(self):
        run = Run.__new__(Run)
        run.state = {}
        run.health = Mock(side_effect=RuntimeError("stop before network checks"))
        with self.assertRaises(RuntimeError):
            run.run()
        self.assertIn("started_at", run.state)
        self.assertIn("journal_since", run.state)

    def test_gap_restarts_window_without_discarding_earlier_logs(self):
        run = Run.__new__(Run)
        before = (dt.datetime.now(UTC)-dt.timedelta(hours=2)).isoformat()
        run.state = {"phase":"soaking", "started_at":before, "journal_since":before, "updated_at":before}
        run.health = Mock(side_effect=RuntimeError("stop before network checks"))
        with self.assertRaises(RuntimeError):
            run.run()
        self.assertGreater(run.state["started_at"], before)
        self.assertEqual(run.state["journal_since"], before)


class ObservationGuards(unittest.TestCase):
    def runner(self):
        run = ObserveRun.__new__(ObserveRun)
        run.state = {"phase": "soaking", "started_at": (dt.datetime.now(UTC)-dt.timedelta(days=1, seconds=10)).isoformat(),
                     "updated_at": dt.datetime.now(UTC).isoformat()}
        run.manifest = {"targets": [], "journal_since": run.state["started_at"], "checks": {},
                        "hosts": [{"hostname": "canary", "ring": 1, "load_result": "/lab/workload.json"}]}
        run.api = Mock(return_value={"current": {"auto_enabled": False, "min_soak_minutes": {"2": 1440}}})
        run.health = Mock()
        run.node_checks = Mock()
        run.remote = Mock(return_value='{"complete":true,"errors":[],"seconds":86400,"counts":{"hashes":1,"file_rounds":1,"socket_rounds":1,"rights_cycles":1}}')
        run.action = Mock(side_effect=AssertionError("observation tried to deploy"))
        run.save = Mock(side_effect=lambda phase, **updates: run.state.update(phase=phase, **updates))
        return run

    def test_completion_reads_both_rings_and_never_deploys(self):
        run = self.runner()
        run.run()
        self.assertEqual(run.state["phase"], "complete")
        self.assertTrue(all(c == call([1, 2]) for c in run.health.call_args_list))
        self.assertTrue(all(c == call([1, 2]) for c in run.node_checks.call_args_list))
        run.action.assert_not_called()
        self.assertTrue(all(c == call("/api/settings") for c in run.api.call_args_list))

    def test_incomplete_failed_or_missing_load_counts_cannot_pass(self):
        for change in ({"complete": False}, {"errors": ["data mismatch"]}, {"seconds": 86394}, {"counts": {}}):
            with self.subTest(change=change):
                run = self.runner()
                result = json.loads(run.remote.return_value)
                result.update(change)
                run.remote.return_value = json.dumps(result)
                with self.assertRaises(ValueError):
                    run.run()
                self.assertNotEqual(run.state["phase"], "complete")

    def test_old_or_failed_runs_cannot_be_reused(self):
        for phase, age in (("failed", 0), ("promoting", 0), ("soaking", 121)):
            run = self.runner()
            run.state.update(phase=phase, updated_at=(dt.datetime.now(UTC)-dt.timedelta(seconds=age)).isoformat())
            with self.assertRaises(ValueError):
                run.run()
            run.api.assert_not_called()

    def test_observation_api_rejects_writes_before_any_request(self):
        run = ObserveRun.__new__(ObserveRun)
        with patch.object(Run, "api") as base:
            for body in ({}, {"version": 0}):
                with self.assertRaises(ValueError):
                    run.api("/api/status", body)
            with self.assertRaises(ValueError):
                run.api("/api/kernels/test/promote")
            with self.assertRaises(ValueError):
                run.action("/api/kernels/test/rollback", {"version": 0})
            base.assert_not_called()

    def test_ring_two_target_change_is_also_a_failure(self):
        run = ObserveRun.__new__(ObserveRun)
        run.manifest = {"targets": [{"kernel": "test", "ring_versions": {"1": 3, "2": 3}}]}
        status = {"tracks": [{"kernel": "test", "ring_versions": {"1": 3, "2": 4}}]}
        with patch.object(Run, "health", return_value=status):
            with self.assertRaisesRegex(ValueError, "ring targets changed"):
                run.health([1, 2])
            status["tracks"][0]["ring_versions"]["2"] = 3
            self.assertEqual(run.health([1, 2]), status)


if __name__ == "__main__":
    unittest.main()

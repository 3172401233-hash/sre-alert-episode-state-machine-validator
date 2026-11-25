import json
import unittest

from validator import GroupKey, validate_episode, validate_payload


ROOT_KEY = GroupKey(alertname="HighLatency", service="checkout")
WINDOW = 30 * 60


def codes(notification):
    return [problem["code"] for problem in notification["problems"]]


class EpisodeValidatorTests(unittest.TestCase):
    def test_duplicate_firing_merges_into_one_continuous_episode(self):
        report = validate_episode(
            group_key=ROOT_KEY,
            window_seconds=WINDOW,
            now=12 * 60,
            firing=[
                {"event_id": "f1", "occurrence_id": "occ-1", "time": 0},
                {"event_id": "f1", "occurrence_id": "occ-1", "time": 0},
                {"event_id": "f2", "occurrence_id": "occ-1", "time": 60},
                {"event_id": "f3", "occurrence_id": "occ-1", "time": 120},
            ],
        )

        self.assertEqual(report["summary"]["episode_count"], 1)
        episode = report["episodes"][0]
        self.assertEqual(episode["status"], "firing")
        self.assertEqual(episode["start"], 0)
        self.assertEqual(episode["duration_seconds"], 12 * 60)
        self.assertEqual(episode["occurrence_count"], 1)
        self.assertEqual(episode["reopen_count"], 0)
        self.assertEqual(
            episode["evidence_event_ids"], ["f1", "f2", "f3"]
        )

        firing_merge = next(
            event for event in report["merged_events"] if event["kind"] == "firing"
        )
        self.assertEqual(firing_merge["event_count"], 4)
        self.assertEqual(firing_merge["duplicate_count"], 3)
        self.assertEqual(firing_merge["source_event_ids"], ["f1", "f2", "f3"])
        self.assertEqual(firing_merge["exact_duplicate_event_ids"], ["f1"])
        self.assertEqual(firing_merge["reason"], "duplicate_firing")

        timeline_kinds = [entry["kind"] for entry in report["timeline"]]
        self.assertIn("duplicate_firing", timeline_kinds)

    def test_overlapping_silences_do_not_hide_recovery_or_reopen(self):
        report = validate_episode(
            group_key=ROOT_KEY,
            window_seconds=WINDOW,
            now=40 * 60,
            firing=[
                {"event_id": "f1", "occurrence_id": "occ-1", "time": 0},
                {"event_id": "f2", "occurrence_id": "occ-2", "time": 20 * 60},
            ],
            resolved=[
                {"event_id": "r1", "occurrence_id": "occ-1", "time": 10 * 60},
                {"event_id": "r2", "occurrence_id": "occ-2", "time": 25 * 60},
            ],
            silences=[
                {
                    "silence_id": "silence-1",
                    "starts_at": 12 * 60,
                    "ends_at": 40 * 60,
                    "group_key": ROOT_KEY.canonical,
                },
                {
                    "silence_id": "silence-2",
                    "starts_at": 15 * 60,
                    "ends_at": 25 * 60,
                    "group_key": ROOT_KEY.canonical,
                },
            ],
            notifications=[
                {
                    "notification_id": "n-f2-bad",
                    "event_id": "f2",
                    "kind": "firing",
                    "status": "sent",
                    "sent_at": 21 * 60,
                },
                {
                    "notification_id": "n-f2-muted",
                    "group_key": ROOT_KEY.canonical,
                    "kind": "firing",
                    "status": "suppressed",
                    "sent_at": 22 * 60,
                },
            ],
        )

        episode = report["episodes"][0]
        self.assertEqual(report["summary"]["episode_count"], 1)
        self.assertEqual(episode["start"], 0)
        self.assertEqual(episode["recovered_at"], 25 * 60)
        self.assertEqual(episode["reopen_count"], 1)
        self.assertEqual(episode["reopens"][0]["at"], 20 * 60)
        self.assertEqual(episode["reopens"][0]["gap_seconds"], 10 * 60)
        self.assertEqual(episode["status"], "recovered")
        self.assertEqual(episode["silence_ids"], ["silence-1", "silence-2"])
        self.assertEqual(episode["silenced_seconds"], 13 * 60)

        merged_windows = next(
            item for item in report["silences"]
            if item.get("report_type") == "merged_silence_windows"
        )
        self.assertEqual(len(merged_windows["windows"]), 1)
        self.assertEqual(
            merged_windows["windows"][0]["silence_ids"],
            ["silence-1", "silence-2"],
        )
        self.assertTrue(merged_windows["windows"][0]["overlapping"])

        bad = next(
            item for item in report["error_notifications"]
            if item["notification_id"] == "n-f2-bad"
        )
        self.assertIn("sent_during_silence", codes(bad))
        muted = next(
            item for item in report["notifications"]
            if item["notification_id"] == "n-f2-muted"
        )
        self.assertEqual(muted["problems"], [])

        kinds = [entry["kind"] for entry in episode["timeline"]]
        self.assertIn("silence_start", kinds)
        self.assertIn("reopened", kinds)

    def test_late_resolved_notification_does_not_close_next_occurrence(self):
        report = validate_episode(
            group_key=ROOT_KEY,
            window_seconds=WINDOW,
            now=30 * 60,
            events=[
                {"event_id": "f1", "occurrence_id": "occ-1", "kind": "firing", "time": 0},
                {"event_id": "f2", "occurrence_id": "occ-2", "kind": "firing", "time": 20 * 60},
                {
                    "event_id": "r1",
                    "occurrence_id": "occ-1",
                    "kind": "resolved",
                    "time": 10 * 60,
                    "received_at": 25 * 60,
                },
            ],
            notifications=[
                {
                    "notification_id": "nr1",
                    "event_id": "r1",
                    "kind": "resolved",
                    "status": "sent",
                    "sent_at": 25 * 60,
                    "applied_occurrence_id": "occ-2",
                }
            ],
        )

        self.assertEqual(report["summary"]["episode_count"], 1)
        episode = report["episodes"][0]
        self.assertEqual(episode["recoveries"][0]["at"], 10 * 60)
        self.assertEqual(episode["reopen_count"], 1)
        self.assertIsNone(episode["recovered_at"])
        self.assertEqual(episode["status"], "firing")

        occurrences = {
            item["occurrence_id"]: item for item in episode["occurrences"]
        }
        self.assertFalse(occurrences["occ-1"]["active"])
        self.assertTrue(occurrences["occ-2"]["active"])

        late_notification = report["error_notifications"][0]
        problem_codes = codes(late_notification)
        self.assertIn("late_resolved_after_next_firing", problem_codes)
        self.assertIn("resolved_closed_wrong_occurrence", problem_codes)
        self.assertEqual(late_notification["occurrence_id"], "occ-1")

    def test_shuffled_events_with_time_correlation_are_reconstructed(self):
        report = validate_episode(
            window_seconds=WINDOW,
            now=30 * 60,
            events=[
                {
                    "event_id": "r1",
                    "kind": "resolved",
                    "startsAt": "1970-01-01T00:00:00Z",
                    "endsAt": "1970-01-01T00:10:00Z",
                },
                {
                    "event_id": "f2",
                    "kind": "firing",
                    "startsAt": "1970-01-01T00:20:00Z",
                },
                {
                    "event_id": "f1",
                    "kind": "firing",
                    "startsAt": "1970-01-01T00:00:00Z",
                },
            ],
            notifications=[
                {
                    "notification_id": "nr1",
                    "event_id": "r1",
                    "status": "sent",
                    "sent_at": "1970-01-01T00:25:00Z",
                }
            ],
        )

        episode = report["episodes"][0]
        self.assertEqual(report["summary"]["episode_count"], 1)
        self.assertEqual(episode["start"], 0)
        self.assertEqual(episode["recoveries"][0]["at"], 600)
        self.assertEqual(episode["reopen_count"], 1)
        self.assertEqual(episode["status"], "firing")
        self.assertIsNone(episode["recovered_at"])

        late = next(
            item for item in report["notifications"]
            if item["notification_id"] == "nr1"
        )
        self.assertIn("late_resolved_after_next_firing", codes(late))

    def test_window_boundary_controls_reopen_vs_new_episode(self):
        within = validate_episode(
            group_key=ROOT_KEY,
            window_seconds=WINDOW,
            now=40 * 60,
            firing=[{"event_id": "f2", "time": 40 * 60}],
            resolved=[{"event_id": "r1", "time": 10 * 60}],
            events=[{"event_id": "f1", "kind": "firing", "time": 0}],
        )
        self.assertEqual(within["summary"]["episode_count"], 1)
        self.assertEqual(within["episodes"][0]["reopen_count"], 1)

        beyond = validate_episode(
            group_key=ROOT_KEY,
            window_seconds=WINDOW,
            now=80 * 60,
            events=[
                {"event_id": "f1", "kind": "firing", "time": 0},
                {"event_id": "r1", "kind": "resolved", "time": 10 * 60},
                {"event_id": "f2", "kind": "firing", "time": 40 * 60 + 1},
            ],
        )
        self.assertEqual(beyond["summary"]["episode_count"], 2)
        first, second = beyond["episodes"]
        self.assertEqual(first["status"], "closed")
        self.assertEqual(first["closed_at"], 40 * 60)
        self.assertEqual(second["status"], "firing")

    def test_group_key_keeps_root_causes_separate_and_evidence_complete(self):
        other = GroupKey(alertname="DiskFull", service="db")
        report = validate_episode(
            window_seconds=WINDOW,
            now=20 * 60,
            events=[
                {"event_id": "a-f1", "group_key": ROOT_KEY, "kind": "firing", "time": 0},
                {"event_id": "b-f1", "group_key": other, "kind": "firing", "time": 60},
                {"event_id": "a-f2", "group_key": ROOT_KEY, "kind": "firing", "time": 120},
            ],
        )

        self.assertEqual(report["summary"]["group_count"], 2)
        keyed = {group["group_key_text"]: group for group in report["groups"]}
        root_group = keyed[ROOT_KEY.canonical]
        other_group = keyed[other.canonical]
        self.assertEqual(root_group["episodes"][0]["evidence_event_ids"], ["a-f1", "a-f2"])
        self.assertEqual(other_group["episodes"][0]["evidence_event_ids"], ["b-f1"])

    def test_failed_and_unknown_notification_statuses_are_errors(self):
        report = validate_episode(
            group_key=ROOT_KEY,
            now=60,
            firing=[{"event_id": "f1", "time": 0}],
            notifications=[
                {"notification_id": "bad-webhook", "status": "failed", "error": "HTTP 500"},
                {"notification_id": "weird", "status": "telepathic"},
            ],
        )

        code_sets = {
            item["notification_id"]: codes(item)
            for item in report["error_notifications"]
        }
        self.assertIn("delivery_failed", code_sets["bad-webhook"])
        self.assertIn("unknown_notification_status", code_sets["weird"])
        self.assertFalse(report["summary"]["notifications_sent"])
        self.assertFalse(report["notifications_sent"])

    def test_payload_and_full_report_are_json_serializable(self):
        report = validate_payload(
            {
                "group_key": ROOT_KEY.canonical,
                "window": "30m",
                "now": "1970-01-01T00:30:00Z",
                "firing": [
                    {"event_id": "f1", "time": 0},
                    {"event_id": "f2", "time": 1200},
                ],
                "resolved": [
                    {"event_id": "r1", "firing_time": 0, "time": 600},
                ],
                "silences": [
                    {"id": "s1", "start": 720, "end": 1400},
                ],
                "notification_status": {
                    "n1": {"event_id": "f2", "status": "suppressed", "sent_at": 1260}
                },
            }
        )

        serialized = json.dumps(report, ensure_ascii=False)
        self.assertIn("g1-episode-1", serialized)
        self.assertEqual(report["window_seconds"], 1800)
        self.assertEqual(report["episodes"][0]["reopen_count"], 1)


if __name__ == "__main__":
    unittest.main()

<!--
Coldline - Task 4.1
Supplied Project 3 material: the settled Task 3.6 recovery runbook, carried into the Project 4
opening checkpoint exactly as Task 3.6 accepted it. It is not student-editable in this Task;
the two files a Task 4.1 pull request may change are submission.yaml and
docs/student/threat-model.md. The inherited runbook check (`poe runbook-contract`) reads this
file and passes as shipped. The blob quoted under Verification shows the shape and the values a
`poe dev-failure-lab` run produces on the supplied stack; treat it as representative, not as
the archived record of one run.
-->
# Recovery runbook — bounded worker outage (Coldline exception pipeline)

Scope: the `coldline-exception-jobs` queue and its consumer, the `worker` service, in the
Compose stack. Trigger: `poe dev-failure-lab`, which stops the worker for ten seconds, submits
five out-of-range readings, and restarts the worker. This runbook is the detection-to-verification
pass for that scenario, written from one run against the live stack.

## Detection

- **Signal.** The main queue's `ApproximateNumberOfMessages` climbed from 0 to 5 while the worker
  was stopped, with `ApproximateNumberOfMessagesNotVisible` at 0 and the dead-letter queue at 0.
  Growing depth with nothing in flight is the signature of an absent consumer. That reading came
  from *outside* the worker — the same host-side `ApproximateNumberOfMessages` query on the queue
  that `poe dev-failure-lab` prints as it runs — which is the only place it was available at all.
- **Where it showed — and where it could not.** No Prometheus series showed this backlog, because
  the only thing that publishes queue depth is the worker that was stopped.
  `coldline_job_queue_stream_length` and `coldline_job_queue_dead_letter_depth` did not go high;
  they stopped, leaving a scrape gap for the whole outage, and the Grafana diagnostics dashboard's
  queue-depth panel held its last value flat while the real depth grew. The Prometheus-side signals
  were therefore the absence itself: that scrape gap, and `up{job="coldline-worker"} == 0` for
  exactly the length of the outage. Looking for a rising depth line here would have found nothing;
  the silence is the first thing to notice.
- **What did not fire.** `ColdlineDeadLetterQueueBacklog` stayed inactive in Alertmanager. It
  watches `coldline_job_queue_dead_letter_depth > 0`, and nothing was dead-lettered: SQS only
  redrives a message after `maxReceiveCount` *actual* receives, and a stopped consumer never
  receives. A silent worker is invisible to that alert by design; the alert covers poison
  messages, not consumer absence.
- **User-visible symptom.** Every submitted reading answered `202 Accepted` and sat at state
  `QUEUED` on `GET /api/v1/exceptions/{id}` for the whole outage. The API was healthy; the
  workflow simply stopped making progress.

## Diagnosis

- **Consumer outage, not dependency outage.** The API kept writing `RECEIVED -> QUEUED` and
  publishing to SQS, so PostgreSQL and LocalStack were both up. `docker compose ps` showed
  `worker` as `exited`. A dependency outage would have shown the reverse: the worker running
  and either crash-looping or leaving messages in flight, and the API failing to persist.
- **Not a poison message.** Zero dead-letter depth and every record still `QUEUED` (never
  `PROCESSING`) ruled out a message the worker kept failing on. A poison message shows as
  `PROCESSING` records, growing `ApproximateReceiveCount`, and eventually dead-letter arrival.
- **Bounded, not growing.** Five readings, no producer still submitting, so the backlog was the
  whole blast radius. Nothing needed to be shed or paused.

## Recovery

- **Action.** Start the consumer: `docker compose start worker` (the lab does this itself;
  by hand it is `poe worker-start`). No message was touched, redriven, or purged.
- **Why it was safe to do without duplicating work.** Each message is the same durable
  exception identity the API persisted as `QUEUED` before publishing; the worker's
  `WorkerApplication.process` moves `QUEUED -> PROCESSING -> COMPLETED` and acknowledges only
  after terminal persistence, and treats a delivery for an already-terminal identity as a safe
  replay. Restarting the consumer therefore cannot summarise a shipment twice, whatever
  redelivery SQS does in the meantime.
- **If messages had reached the dead-letter queue.** Only possible for a message that was
  mid-receive when the container stopped and later expired back onto the queue with its receive
  count spent. Recovery is then the Task 3.3 path: receive from `coldline-exception-jobs-dlq`,
  send the same body to `coldline-exception-jobs`, delete from the DLQ (`poe redrive`, or the
  lab's own defensive redrive). The redriven message carries the same exception identity, so
  the same idempotency argument holds.
- **What I would not do.** Not restart PostgreSQL or LocalStack (they were healthy; a restart
  would lose the non-persisted LocalStack queue contents), and not purge the queue (that turns a
  delayed workflow into a lost one).

## Verification

- **Records.** All five exception ids reached `COMPLETED`; none `FAILED`; each carries a
  summary. Re-fetching them a second time returned identical records.
- **Queue.** `ApproximateNumberOfMessages` and `ApproximateNumberOfMessagesNotVisible` on the
  main queue back to 0; dead-letter depth 0; zero messages redriven.
- **Telemetry.** `up{job="coldline-worker"}` returned to 1 and the scrape gap closed:
  `coldline_job_queue_stream_length` resumed reporting and read 0. The alert stayed inactive
  throughout, which is the correct outcome for this fault.
- **Evidence.** The lab's evidence blob, of this shape and with these values on the supplied
  stack:

```json
{
  "fault": "consumer_outage",
  "target_service": "worker",
  "worker_stopped_seconds": 10.0,
  "exception_ids": ["<five exception ids>"],
  "queue_depth_while_stopped": 5,
  "dead_letter_depth_while_stopped": 0,
  "redriven_messages": 0,
  "states": {"<each exception id>": "COMPLETED"},
  "final_queue_depth": 0,
  "final_dead_letter_depth": 0,
  "recovery_seconds": 8.1,
  "outcome": "recovered"
}
```

- **Exit.** `poe dev-failure-lab` exited 0. The incident is over when the records are terminal,
  both depths are zero, and the depth gauge is reporting again — not when the worker container
  merely shows `running`.

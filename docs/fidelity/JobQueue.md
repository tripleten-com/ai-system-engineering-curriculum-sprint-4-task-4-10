# JobQueue fidelity

Task 3.3 replaces the active supplied adapter. Redis Streams is retired as the `JobQueue`
transport; the active adapter is now LocalStack SQS, with a bound dead-letter queue. Redis
itself keeps running in `compose.yaml` only because an earlier checkpoint's own contract test
(`tests/contract/test_telemetry_repair.py`) still exercises it directly — it is no longer read
by any composition root and carries no production traffic.

The active adapter proves local publication, long-poll consumption, staleness recovery through
SQS's own visibility timeout (no application polling loop), a bounded number of delivery
attempts enforced by the queue's own redrive policy, automatic dead-letter arrival once that
bound is exceeded, and acknowledgement by receipt handle after terminal persistence. It also
carries the W3C trace context in a message attribute, which is what lets the worker continue
the API's trace: `tests/unit/adapters/test_sqs_trace_carrier.py` proves the carrier without a
stack, and the end-to-end check proves the joined trace against the running one.

LocalStack's SQS emulation is not equivalent to managed Amazon SQS. This local implementation
does not claim IAM enforcement, cross-region replication, at-least-once delivery under real
network partitions, managed-service durability guarantees, availability, or cost. Queue and
dead-letter-queue provisioning happens once, from the initializer, against a single LocalStack
container with no replication, backup, authentication, or production availability guarantee.
`ApproximateNumberOfMessages` and `ApproximateReceiveCount` are approximations, as their names
say; they are exposed only as local diagnostics and exercise evidence, not as an exact count of
outstanding work.

The redrive policy's `maxReceiveCount` is student-configured (`queue_max_receive_count` in
`compose.yaml`, bounded to `[1, 10]`). A value of `1` is within that Field's bounds but is a
functionally wrong choice: it gives a delivery zero tolerance for a single transient failure,
redirecting to the dead-letter queue on the very next receive instead of allowing one retry.
`tests/contract/runtime_adapters.py` asserts this directly against the deployed production
queue, not only against its own throwaway exercise queue.

## ECS fidelity limits (Task 3.6)

<!--
Coldline - Task 4.1
Supplied Project 3 material: Task 3.3's record, unchanged above, plus the settled ECS section
Task 3.6 accepted. Both are carried into the Project 4 opening checkpoint and neither is
student-editable here; the two files a Task 4.1 pull request may change are submission.yaml
and docs/student/threat-model.md. Codes ECS-01..ECS-04 are the ones the inherited
`poe fidelity-check` requires; ECS-05 is a further code the record chose to state.
-->

The development failure lab stops and starts one Compose `worker` container on one host. That is
a local fault control. Nothing it shows transfers to the same worker running as an Amazon ECS
service behind a managed queue and a managed database:

- ECS-01: Task placement is unproven. Compose ran exactly one worker on one host with no
  placement strategy, no bin-packing across instances, no placement constraints, and no capacity
  provider; nothing here shows that a replacement task could be placed at all when the cluster
  is at capacity, or where it would land.
- ECS-02: Service-scheduler replacement is unproven. `docker compose start worker` was an
  operator (or script) action taken on a known-stopped container. An ECS service scheduler
  notices a stopped or unhealthy task itself and launches a replacement to hold `desiredCount`,
  with its own detection latency, launch time, and back-off on repeated failures — none of which
  this lab measured, and none of which a `restart: unless-stopped` policy on one host stands in
  for.
- ECS-03: Autoscaling is unproven. The five-message backlog was drained by the one worker that
  came back, serially, at the supplied 250 ms model latency. ECS Service Auto Scaling driven by
  queue depth (or backlog per task) would add consumers under a real backlog; how many, how fast,
  and whether several concurrent consumers still recover every reading exactly once was never
  exercised here.
- ECS-04: Health-check grace and load-balancer behaviour are unproven. Compose's healthcheck and
  `up --wait` gate one container's readiness on one host. They are not an ECS
  `healthCheckGracePeriodSeconds`, not an ALB target-group health check, and not target
  deregistration draining for the API; a task killed during warm-up, or traffic routed to a
  target still draining, cannot happen in this topology and so cannot be observed in it.
- ECS-05: Multi-AZ failover is unproven. Stopping and starting one container on one host is not
  a Multi-AZ failover of any managed dependency, and a single-host worker restart says nothing
  about rescheduling a task into another Availability Zone when one is lost.

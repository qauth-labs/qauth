CREATE TABLE "event_deliveries" (
	"id" uuid PRIMARY KEY DEFAULT uuidv7() NOT NULL,
	"destination_kind" varchar(32) NOT NULL,
	"destination_id" varchar(255) NOT NULL,
	"event_id" uuid NOT NULL,
	"realm_id" uuid NOT NULL,
	"event_xid" "xid8" NOT NULL,
	"event_seq" bigint NOT NULL,
	"event_time" bigint NOT NULL,
	"status" varchar(16) DEFAULT 'pending' NOT NULL,
	"attempt_count" integer DEFAULT 0 NOT NULL,
	"next_attempt_at" bigint NOT NULL,
	"locked_until" bigint,
	"last_status_code" smallint,
	"last_error_class" varchar(64),
	"created_at" bigint DEFAULT (EXTRACT(EPOCH FROM NOW())::bigint * 1000) NOT NULL,
	"updated_at" bigint DEFAULT (EXTRACT(EPOCH FROM NOW())::bigint * 1000) NOT NULL,
	"finished_at" bigint,
	CONSTRAINT "event_deliveries_event_destination_unique" UNIQUE("event_id","destination_kind","destination_id"),
	CONSTRAINT "event_deliveries_status_known" CHECK ("event_deliveries"."status" in ('pending', 'delivered', 'failed')),
	CONSTRAINT "event_deliveries_destination_kind_not_empty" CHECK ("event_deliveries"."destination_kind" <> ''),
	CONSTRAINT "event_deliveries_destination_id_not_empty" CHECK ("event_deliveries"."destination_id" <> ''),
	CONSTRAINT "event_deliveries_attempt_count_valid" CHECK ("event_deliveries"."attempt_count" >= 0),
	CONSTRAINT "event_deliveries_last_status_code_valid" CHECK ("event_deliveries"."last_status_code" is null or "event_deliveries"."last_status_code" between 100 and 599),
	CONSTRAINT "event_deliveries_finished_when_done" CHECK (("event_deliveries"."status" = 'pending') = ("event_deliveries"."finished_at" is null)),
	CONSTRAINT "event_deliveries_lease_while_pending" CHECK ("event_deliveries"."locked_until" is null or "event_deliveries"."status" = 'pending')
);
--> statement-breakpoint
CREATE TABLE "event_delivery_positions" (
	"realm_id" uuid PRIMARY KEY NOT NULL,
	"xid" "xid8" NOT NULL,
	"seq" bigint NOT NULL,
	"updated_at" bigint DEFAULT (EXTRACT(EPOCH FROM NOW())::bigint * 1000) NOT NULL,
	CONSTRAINT "event_delivery_positions_seq_valid" CHECK ("event_delivery_positions"."seq" >= 0)
);
--> statement-breakpoint
ALTER TABLE "event_deliveries" ADD CONSTRAINT "event_deliveries_event_id_events_id_fk" FOREIGN KEY ("event_id") REFERENCES "public"."events"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
CREATE INDEX "idx_event_deliveries_due" ON "event_deliveries" USING btree ("destination_kind","destination_id","next_attempt_at") WHERE "event_deliveries"."status" = 'pending';--> statement-breakpoint
CREATE INDEX "idx_event_deliveries_pending_position" ON "event_deliveries" USING btree ("realm_id","event_xid","event_seq") WHERE "event_deliveries"."status" = 'pending';--> statement-breakpoint
CREATE INDEX "idx_event_deliveries_pending_time" ON "event_deliveries" USING btree ("event_time") WHERE "event_deliveries"."status" = 'pending';
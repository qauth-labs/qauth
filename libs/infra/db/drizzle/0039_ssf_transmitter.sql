-- #410 (ADR-018 §3, ADR-019 Decision 8): the Shared Signals Framework
-- transmitter. Its streams (one per receiver and realm) and the subjects each
-- receiver added, the per-realm switch (off), and an index that finds a
-- destination's latest failed delivery for the stream status endpoint.
--
-- Expand only: two new tables, a column with a default, and an index. The
-- index takes a SHARE lock on event_deliveries while it builds, which holds
-- back the delivery role's writes for that time; the table holds only rows
-- the retention job has not yet removed.
CREATE TABLE "ssf_stream_subjects" (
	"stream_id" uuid NOT NULL,
	"subject_key" varchar(2048) NOT NULL,
	"subject" jsonb NOT NULL,
	"event_subject_type" varchar(32),
	"event_subject_id" varchar(255),
	"verified" boolean DEFAULT true NOT NULL,
	"created_at" bigint DEFAULT (EXTRACT(EPOCH FROM NOW())::bigint * 1000) NOT NULL,
	CONSTRAINT "ssf_stream_subjects_pk" PRIMARY KEY("stream_id","subject_key"),
	CONSTRAINT "ssf_stream_subjects_event_subject_complete" CHECK (("ssf_stream_subjects"."event_subject_type" is null) = ("ssf_stream_subjects"."event_subject_id" is null)),
	CONSTRAINT "ssf_stream_subjects_subject_is_object" CHECK (jsonb_typeof("ssf_stream_subjects"."subject") = 'object')
);
--> statement-breakpoint
CREATE TABLE "ssf_streams" (
	"id" uuid PRIMARY KEY DEFAULT uuidv7() NOT NULL,
	"realm_id" uuid NOT NULL,
	"receiver_client_id" uuid NOT NULL,
	"audience" varchar(255) NOT NULL,
	"events_requested" jsonb DEFAULT '[]'::jsonb NOT NULL,
	"delivery_method" varchar(64) NOT NULL,
	"endpoint_url" varchar(2048) NOT NULL,
	"authorization_header" text,
	"description" varchar(1024),
	"status" varchar(16) DEFAULT 'enabled' NOT NULL,
	"status_reason" varchar(255),
	"created_at" bigint DEFAULT (EXTRACT(EPOCH FROM NOW())::bigint * 1000) NOT NULL,
	"updated_at" bigint DEFAULT (EXTRACT(EPOCH FROM NOW())::bigint * 1000) NOT NULL,
	CONSTRAINT "ssf_streams_receiver_unique" UNIQUE("realm_id","receiver_client_id"),
	CONSTRAINT "ssf_streams_status_known" CHECK ("ssf_streams"."status" in ('enabled', 'paused', 'disabled')),
	CONSTRAINT "ssf_streams_delivery_method_known" CHECK ("ssf_streams"."delivery_method" in ('urn:ietf:rfc:8935')),
	CONSTRAINT "ssf_streams_audience_not_empty" CHECK ("ssf_streams"."audience" <> ''),
	CONSTRAINT "ssf_streams_endpoint_url_not_empty" CHECK ("ssf_streams"."endpoint_url" <> ''),
	CONSTRAINT "ssf_streams_events_requested_is_array" CHECK (jsonb_typeof("ssf_streams"."events_requested") = 'array')
);
--> statement-breakpoint
ALTER TABLE "realms" ADD COLUMN "ssf_transmitter_enabled" boolean DEFAULT false NOT NULL;--> statement-breakpoint
ALTER TABLE "ssf_stream_subjects" ADD CONSTRAINT "ssf_stream_subjects_stream_id_ssf_streams_id_fk" FOREIGN KEY ("stream_id") REFERENCES "public"."ssf_streams"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "ssf_streams" ADD CONSTRAINT "ssf_streams_realm_id_realms_id_fk" FOREIGN KEY ("realm_id") REFERENCES "public"."realms"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "ssf_streams" ADD CONSTRAINT "ssf_streams_receiver_client_id_oauth_clients_id_fk" FOREIGN KEY ("receiver_client_id") REFERENCES "public"."oauth_clients"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
CREATE INDEX "idx_event_deliveries_last_error" ON "event_deliveries" USING btree ("destination_kind","destination_id","updated_at") WHERE "event_deliveries"."last_error_class" is not null;

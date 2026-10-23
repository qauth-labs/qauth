CREATE TABLE "events" (
	"seq" bigint PRIMARY KEY GENERATED ALWAYS AS IDENTITY (sequence name "events_seq_seq" INCREMENT BY 1 MINVALUE 1 MAXVALUE 9223372036854775807 START WITH 1 CACHE 1),
	"xid" "xid8" DEFAULT pg_current_xact_id() NOT NULL,
	"id" uuid NOT NULL,
	"realm_id" uuid NOT NULL,
	"category" varchar(16) NOT NULL,
	"type" varchar(255) NOT NULL,
	"time" bigint NOT NULL,
	"actor_type" varchar(32),
	"actor_id" varchar(255),
	"actor_delegation_chain" jsonb,
	"subject_type" varchar(32),
	"subject_id" varchar(255),
	"client_id" varchar(255),
	"request_id" varchar(128),
	"request_ip" varchar(45),
	"request_user_agent" varchar(1024),
	"data" jsonb NOT NULL,
	"schema_version" smallint NOT NULL,
	CONSTRAINT "events_id_unique" UNIQUE("id"),
	CONSTRAINT "events_id_uuidv7" CHECK (uuid_extract_version("events"."id") = 7),
	CONSTRAINT "events_category_known" CHECK ("events"."category" in ('user', 'admin')),
	CONSTRAINT "events_type_not_empty" CHECK ("events"."type" <> ''),
	CONSTRAINT "events_data_is_object" CHECK (jsonb_typeof("events"."data") = 'object'),
	CONSTRAINT "events_actor_delegation_chain_is_array" CHECK ("events"."actor_delegation_chain" is null or jsonb_typeof("events"."actor_delegation_chain") = 'array'),
	CONSTRAINT "events_actor_has_type" CHECK ("events"."actor_type" is not null or ("events"."actor_id" is null and "events"."actor_delegation_chain" is null)),
	CONSTRAINT "events_subject_complete" CHECK (("events"."subject_type" is null) = ("events"."subject_id" is null)),
	CONSTRAINT "events_schema_version_positive" CHECK ("events"."schema_version" >= 1)
);
--> statement-breakpoint
CREATE INDEX "idx_events_realm_position" ON "events" USING btree ("realm_id","xid","seq");--> statement-breakpoint
CREATE INDEX "idx_events_realm_type" ON "events" USING btree ("realm_id","type");--> statement-breakpoint
CREATE INDEX "idx_events_subject_id" ON "events" USING btree ("subject_id");--> statement-breakpoint
CREATE INDEX "idx_events_time" ON "events" USING btree ("time");
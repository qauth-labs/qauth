-- #949: record which plugin wrote each realm's state of an AuthMethod plugin,
-- its npm package and its AuthMethod type, beside the id the row is keyed by.
-- The plugin runtime treats a row whose package or type is not the installed
-- plugin's as off, and its secrets, which are sealed under a context that
-- names both, do not open: a deployment that puts another package behind the
-- same id inherits neither the realm's switch, its config nor its secrets.
--
-- Two nullable columns with no default, so Postgres adds them without
-- rewriting the table, and every existing row gets NULL in both: a state
-- written before this migration names no package, and counts as another
-- package's until a configure writes it again. A release before this one
-- never names the columns: its insert leaves both NULL, and its update keeps
-- them. Forward-only: nothing is rewritten.
--
-- The CHECKs hold the recorded forms: both columns set or neither, a package
-- name that is not empty, and a type under the contract's type rule. Every
-- existing row passes them (NULL in both).
ALTER TABLE "realm_auth_method_plugins" ADD COLUMN "plugin_package" varchar(214);--> statement-breakpoint
ALTER TABLE "realm_auth_method_plugins" ADD COLUMN "plugin_type" varchar(63);--> statement-breakpoint
ALTER TABLE "realm_auth_method_plugins" ADD CONSTRAINT "realm_auth_method_plugins_binding_pair" CHECK (("realm_auth_method_plugins"."plugin_package" IS NULL) = ("realm_auth_method_plugins"."plugin_type" IS NULL));--> statement-breakpoint
ALTER TABLE "realm_auth_method_plugins" ADD CONSTRAINT "realm_auth_method_plugins_plugin_package_form" CHECK ("realm_auth_method_plugins"."plugin_package" <> '');--> statement-breakpoint
ALTER TABLE "realm_auth_method_plugins" ADD CONSTRAINT "realm_auth_method_plugins_plugin_type_form" CHECK ("realm_auth_method_plugins"."plugin_type" ~ '^[a-z][a-z0-9_]{0,62}$');

CREATE TABLE "integration_deliveries" (
	"id" uuid PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"organization_id" uuid,
	"project_id" uuid,
	"integration_id" uuid,
	"scan_id" uuid,
	"provider" text NOT NULL,
	"action" text DEFAULT 'notify' NOT NULL,
	"status" text DEFAULT 'pending' NOT NULL,
	"attempts" integer DEFAULT 0 NOT NULL,
	"max_attempts" integer DEFAULT 3 NOT NULL,
	"next_attempt_at" timestamp,
	"delivered_at" timestamp,
	"external_url" text,
	"last_error" text,
	"payload" jsonb DEFAULT '{}'::jsonb,
	"created_at" timestamp DEFAULT now() NOT NULL,
	"updated_at" timestamp DEFAULT now() NOT NULL
);
--> statement-breakpoint
ALTER TABLE "integration_deliveries" ADD CONSTRAINT "integration_deliveries_organization_id_organizations_id_fk" FOREIGN KEY ("organization_id") REFERENCES "public"."organizations"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "integration_deliveries" ADD CONSTRAINT "integration_deliveries_project_id_projects_id_fk" FOREIGN KEY ("project_id") REFERENCES "public"."projects"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "integration_deliveries" ADD CONSTRAINT "integration_deliveries_integration_id_integrations_id_fk" FOREIGN KEY ("integration_id") REFERENCES "public"."integrations"("id") ON DELETE set null ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "integration_deliveries" ADD CONSTRAINT "integration_deliveries_scan_id_scans_id_fk" FOREIGN KEY ("scan_id") REFERENCES "public"."scans"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
CREATE INDEX "integration_deliveries_project_idx" ON "integration_deliveries" USING btree ("project_id");--> statement-breakpoint
CREATE INDEX "integration_deliveries_scan_idx" ON "integration_deliveries" USING btree ("scan_id");--> statement-breakpoint
CREATE INDEX "integration_deliveries_integration_idx" ON "integration_deliveries" USING btree ("integration_id");--> statement-breakpoint
CREATE INDEX "integration_deliveries_status_idx" ON "integration_deliveries" USING btree ("status");--> statement-breakpoint
CREATE INDEX "integration_deliveries_next_attempt_idx" ON "integration_deliveries" USING btree ("next_attempt_at");
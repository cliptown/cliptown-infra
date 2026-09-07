# Shared Auth topology

DEN-2843 extends Cliptown's provider scaffolds with explicit Shared Auth
customer/admin boundaries. Customer web/API services use both auth databases;
admin web/API services use both independent admin databases and never customer
fallbacks. Supabase's shared `oresoftware` runtime placement remains a temporary
schema-isolated configuration, while `cliptown` is the target Supabase org and
the dedicated Neon org. Admin and sensitive operations require strict paired
proof. Run `node shared-auth/validate.mjs`.

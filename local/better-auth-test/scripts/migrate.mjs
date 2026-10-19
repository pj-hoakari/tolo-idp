import { getMigrations } from "better-auth/db/migration";
import { auth } from "../src/lib/auth.ts";

const migration = await getMigrations(auth.options);
await migration.runMigrations();
console.log("Better Auth database schema is ready.");
process.exit(0);

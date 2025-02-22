import { fileURLToPath } from "url";
import path from "path"; // Import path module

const __filename = fileURLToPath(import.meta.url);

export const __dirname = path.resolve(path.dirname(__filename), "./../");

// Type guard function to check if err is a database error
export function isDatabaseError(err: unknown): err is { code: string } {
  return (
    typeof err === "object" &&
    err !== null &&
    "code" in err &&
    typeof (err as { code: string }).code === "string"
  );
}

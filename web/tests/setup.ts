import "@testing-library/jest-dom";

// Stub Next.js server-only module resolution
vi.mock("server-only", () => ({}));

// Default encryption key for tests — 64 hex chars (32 bytes)
process.env["ENCRYPTION_KEY"] = "a".repeat(64);
process.env["DATABASE_URL"] = "postgresql://test:test@localhost/test";
process.env["AUTH_URL"] = "http://localhost:3000";
process.env["AUTH_SECRET"] = "test-secret-at-least-32-chars-long-here";

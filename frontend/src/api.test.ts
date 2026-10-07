import { afterEach, describe, expect, it, vi } from "vitest";
import { api } from "./api";

afterEach(() => vi.unstubAllGlobals());

describe("API client", () => {
  it("uses the pre-auth CSRF token for login and includes cookies", async () => {
    const fetchMock = vi.fn()
      .mockResolvedValueOnce(new Response(JSON.stringify({ csrf_token: "pre-auth-token" })))
      .mockResolvedValueOnce(new Response(JSON.stringify({
        user: { id: "1", email: "user@example.test", display_name: null, role: "customer", created_at: null },
        message: "Signed in.",
        csrf_token: "session-token",
      })));
    vi.stubGlobal("fetch", fetchMock);

    const result = await api.login("user@example.test", "a-long-test-password");

    expect(result.user.role).toBe("customer");
    expect(fetchMock).toHaveBeenNthCalledWith(1, "/api/auth/csrf", expect.objectContaining({ credentials: "include" }));
    const loginInit = fetchMock.mock.calls[1][1] as RequestInit;
    expect((loginInit.headers as Headers).get("X-CSRF-Token")).toBe("pre-auth-token");
    expect(loginInit.credentials).toBe("include");
  });

  it("normalizes the stable backend error envelope", async () => {
    vi.stubGlobal("fetch", vi.fn().mockResolvedValue(new Response(JSON.stringify({
      error: { code: "rate_limited", message: "Too many requests." },
    }), { status: 429, headers: { "Retry-After": "42" } })));

    await expect(api.sendMessage("hello")).rejects.toMatchObject({
      status: 429,
      code: "rate_limited",
      message: "Too many requests.",
      retryAfter: 42,
    });
  });
});

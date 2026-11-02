using System.Collections.Concurrent;
using System.Net;
using System.Net.Http.Json;
using System.Text.Json.Nodes;
using Microsoft.AspNetCore.Hosting;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using SecureLab.Api.Data;

namespace SecureLab.Api.Tests;

public sealed class AuthorizationAuditTests
{
    private sealed class Sink : ILoggerProvider
    {
        public ConcurrentQueue<Dictionary<string, object?>> Events { get; } = new();
        public ILogger CreateLogger(string categoryName) => new Writer(this, categoryName);
        public void Dispose() { }
        private sealed class Writer(Sink sink, string category) : ILogger
        {
            public IDisposable? BeginScope<TState>(TState state) where TState : notnull => null;
            public bool IsEnabled(LogLevel level) => category == "SecureLab.Authorization";
            public void Log<TState>(LogLevel level, EventId eventId, TState state, Exception? exception, Func<TState, Exception?, string> formatter)
            {
                if (IsEnabled(level) && state is IEnumerable<KeyValuePair<string, object?>> fields)
                    sink.Events.Enqueue(fields.ToDictionary(x => x.Key, x => x.Value));
            }
        }
    }

    [Fact]
    public async Task A09_DeniedTriage_HasOnlySafeAuditFields_AndMatchesResponseTrace()
    {
        using var factory = new SecureLabApiFactory();
        var sink = new Sink();
        using var host = factory.WithWebHostBuilder(b => b.ConfigureServices(s => s.AddSingleton<ILoggerProvider>(sink)));
        using var client = host.CreateClient(new() { BaseAddress = new Uri("https://localhost"), AllowAutoRedirect = false });
        var password = Environment.GetEnvironmentVariable("SeedUsers__Password")!;
        using var login = await client.PostAsJsonAsync("/api/auth/login", new { userName = "alice", password });
        Assert.Equal(HttpStatusCode.NoContent, login.StatusCode);
        using var denied = await client.PostAsJsonAsync($"/api/incidents/{DbSeeder.AliceIncidentId}/triage", new { password = "never-log-this-body", role = "Analyst" });
        Assert.Equal(HttpStatusCode.Forbidden, denied.StatusCode);
        var body = (await denied.Content.ReadFromJsonAsync<JsonObject>())!;
        var entry = Assert.Single(sink.Events);
        Assert.Equal(new[] { "Action", "EventName", "ResourceId", "Result", "SubjectId", "TraceId", "UtcTime", "{OriginalFormat}" }, entry.Keys.Order(StringComparer.Ordinal));
        Assert.Equal("authorization.denied", entry["EventName"]);
        Assert.Equal(DbSeeder.AliceId, entry["SubjectId"]);
        Assert.Equal(DbSeeder.AliceIncidentId, entry["ResourceId"]);
        Assert.Equal("denied", entry["Result"]);
        Assert.Equal(body["traceId"]!.GetValue<string>(), entry["TraceId"]);
        var serialized = System.Text.Json.JsonSerializer.Serialize(entry);
        Assert.DoesNotContain(password, serialized);
        Assert.DoesNotContain("never-log-this-body", serialized);
        Assert.DoesNotContain("Cookie", serialized);
    }
}

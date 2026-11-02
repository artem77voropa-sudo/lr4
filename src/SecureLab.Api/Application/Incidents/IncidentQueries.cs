using Microsoft.EntityFrameworkCore;
using SecureLab.Api.Data;
using SecureLab.Api.Data.Entities;
using SecureLab.Api.Presentation.Contracts;

namespace SecureLab.Api.Application.Incidents;

public sealed class IncidentQueries(
    SecureLabDbContext dbContext,
    ILogger<IncidentQueries> logger,
    IncidentAccess access)
{
    private static readonly IReadOnlyList<string> SeverityOrder =
        Enum.GetValues<IncidentSeverity>().Select(severity => severity.ToString()).ToList();

    public async Task<IReadOnlyList<IncidentListItemResponse>> GetListAsync(
        IncidentStatus? status,
        CancellationToken cancellationToken)
    {
        logger.LogInformation("Loading incidents with status filter {Status}", status);

        var query = access.Visible(dbContext.Incidents.AsNoTracking());
        if (status is not null)
        {
            query = query.Where(incident => incident.Status == status);
        }

        return await query
            .OrderByDescending(incident => incident.CreatedAtUtc)
            .Select(incident => new IncidentListItemResponse(
                incident.Id,
                incident.Title,
                incident.Severity.ToString(),
                incident.Status.ToString(),
                incident.OccurredAtUtc,
                incident.CreatedAtUtc))
            .ToListAsync(cancellationToken);
    }

    public async Task<IReadOnlyList<IncidentSeveritySummaryResponse>> GetSeveritySummaryAsync(CancellationToken cancellationToken = default)
{
    // 1. Отримуємо дані з БД без відстеження та групуємо за Severity
    var dbCounts = await dbContext.Incidents
        .AsNoTracking()
        .GroupBy(i => i.Severity)
        .Select(g => new
        {
            Severity = g.Key,
            Count = g.Count()
        })
        .ToListAsync(cancellationToken);

    // 2. Створюємо словник для зручного пошуку
    var countsDict = dbCounts.ToDictionary(x => x.Severity, x => x.Count);

    // 3. Доповнюємо відсутні групи нулями та формуємо сталий порядок
    var allSeverities = Enum.GetValues<IncidentSeverity>();
    var result = new List<IncidentSeveritySummaryResponse>();

    foreach (var severity in allSeverities)
    {
        var severityString = severity.ToString();
        var count = countsDict.TryGetValue(severity, out var c) ? c : 0;
        result.Add(new IncidentSeveritySummaryResponse(severityString, count));
    }

    return result;
}

    public Task<IncidentDetailsResponse?> GetDetailsAsync(Guid id, CancellationToken cancellationToken)
    {
        logger.LogInformation("Loading incident {IncidentId}", id);

        return access.Visible(dbContext.Incidents.AsNoTracking())
            .Where(incident => incident.Id == id)
            .Select(incident => new IncidentDetailsResponse(
                incident.Id,
                incident.Title,
                incident.Description,
                incident.Severity.ToString(),
                incident.Status.ToString(),
                incident.OccurredAtUtc,
                incident.CreatedAtUtc,
                incident.Owner.DisplayName,
                incident.Comments
                    .Where(comment => !comment.IsInternal || access.IsAnalyst)
                    .OrderBy(comment => comment.CreatedAtUtc)
                    .Select(comment => new IncidentCommentResponse(
                        comment.Id,
                        comment.Author.DisplayName,
                        comment.Text,
                        comment.CreatedAtUtc))
                    .ToList()))
            .SingleOrDefaultAsync(cancellationToken);
    }
}

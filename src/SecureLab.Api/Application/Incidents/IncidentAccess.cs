using System.Security.Claims;
using SecureLab.Api.Data;
using SecureLab.Api.Data.Entities;

namespace SecureLab.Api.Application.Incidents;

// One rule shared by list, details, mutations and child-resource access.
public sealed class IncidentAccess(IHttpContextAccessor accessor)
{
    private ClaimsPrincipal User => accessor.HttpContext?.User ?? new ClaimsPrincipal();
    public Guid UserId => Guid.TryParse(User.FindFirstValue(ClaimTypes.NameIdentifier), out var id) ? id : Guid.Empty;
    public bool IsAnalyst => User.Identity?.IsAuthenticated == true && User.IsInRole(DbSeeder.AnalystRole);
    public bool IsReporter => User.Identity?.IsAuthenticated == true && User.IsInRole(DbSeeder.ReporterRole);

    public IQueryable<Incident> Visible(IQueryable<Incident> query)
    {
        var analyst = IsAnalyst;
        var reporter = IsReporter;
        var userId = UserId;
        return query.Where(row => analyst || (reporter && row.OwnerUserId == userId));
    }

    public bool CanRead(Incident row) => IsAnalyst || (IsReporter && row.OwnerUserId == UserId);
    public bool CanUpdate(Incident row) => IsReporter && row.OwnerUserId == UserId;
    public bool CanDelete(Incident row) => CanUpdate(row) && row.Status == IncidentStatus.New;
    public bool CanTriage(Incident row) => IsAnalyst && row.Status == IncidentStatus.New;
    public bool CanReadComment(IncidentComment comment) => CanRead(comment.Incident) && (!comment.IsInternal || IsAnalyst);
}

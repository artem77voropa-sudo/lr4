using Microsoft.EntityFrameworkCore;
using SecureLab.Api.Data;
using SecureLab.Api.Data.Entities;
namespace SecureLab.Api.Scaffolding;
// Deliberately vulnerable LOCAL study snapshot. Never deploy.
public static class Lab04Vulnerable
{
 public sealed record Input(string Description);
 public static void MapLab04Vulnerable(this WebApplication app)
 {
  app.MapPut("/api/incidents/{id:guid}", async(Guid id, Input input, SecureLabDbContext db) => {
   var row = await db.Incidents.FindAsync(id);
   if(row is null) return Results.NotFound();
   row.Description=input.Description;
   await db.SaveChangesAsync();
   return Results.NoContent();
  }).RequireAuthorization();
  app.MapPost("/api/incidents/{id:guid}/triage", async(Guid id, SecureLabDbContext db) => {
   var row = await db.Incidents.FindAsync(id);
   if(row is null) return Results.NotFound();
   row.Status=IncidentStatus.Triaged;
   await db.SaveChangesAsync();
   return Results.NoContent();
  }).RequireAuthorization();
 }
}

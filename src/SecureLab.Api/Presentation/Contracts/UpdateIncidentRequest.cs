namespace SecureLab.Api.Presentation.Contracts;

// Unknown fields are ignored. Ownership, severity and status are never bound here.
public sealed record UpdateIncidentRequest(string? Title, string? Description);

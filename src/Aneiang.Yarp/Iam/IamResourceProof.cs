using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

namespace Aneiang.Yarp.Iam;

// One-operation destination attestation, not an alternative token issuer or resource owner resolver.
public static class IamResourceProof
{
    public static string Create(IamOperationPolicy policy, IamEntitlementSnapshot snapshot, string authorization,
        IamGatewayOptions settings, string method)
    {
        if (!policy.ResourceScopeRequired || !settings.ResourceSigningKeys.TryGetValue(policy.BackendServiceCode, out var secret))
            throw new IamContractException("resource_proof_unconfigured");
        byte[] key;
        try { key = Convert.FromBase64String(secret); }
        catch (FormatException) { throw new IamContractException("resource_proof_key_invalid"); }
        if (key.Length < 32) throw new IamContractException("resource_proof_key_invalid");
        try
        {
            var grants = snapshot.Grants.Where(g => policy.RequiredPermissions.Contains(g.PermissionCode, StringComparer.Ordinal)).ToArray();
            if (grants.Length > 128) throw new IamContractException("resource_proof_oversized");
            var bytes = JsonSerializer.SerializeToUtf8Bytes(new
            {
                schemaVersion = 1, applicationId = snapshot.ApplicationId, principalId = snapshot.PrincipalId,
                operationKey = policy.OperationKey, backendServiceCode = policy.BackendServiceCode, httpMethod = method,
                tokenHash = Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(authorization))).ToLowerInvariant(),
                issuedAt = snapshot.IssuedAt, expiresAt = snapshot.ExpiresAt, revision = snapshot.Revision, isActive = snapshot.IsActive,
                grants = grants.Select(g => new { g.PermissionCode, g.ScopeKind, g.ScopeId, g.ExpiresAt }).ToArray()
            }, IamBundleWireProtocol.JsonOptions);
            var header = Convert.ToBase64String(bytes) + "." + Convert.ToBase64String(HMACSHA256.HashData(key, bytes));
            if (header.Length > 24576) throw new IamContractException("resource_proof_oversized");
            return header;
        }
        finally { CryptographicOperations.ZeroMemory(key); }
    }
}

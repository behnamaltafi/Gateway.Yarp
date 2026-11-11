using System.Text.Json;

namespace Aneiang.Yarp.Iam;

public static class IamPolicyBundleValidator
{
    public static bool TryValidate(IamPolicyBundle? bundle, DateTimeOffset now, out string reason)
    {
        if (bundle is null) { reason = "bundle_missing"; return false; }
        try
        {
            var decoded = IamBundleWireProtocol.Decode(new(1, bundle.Revision, bundle.Hash, bundle.ValidatedUntil, bundle.PolicyContentBase64), now);
            if (bundle.SchemaVersion != "1.0" || bundle.RouteManifestHash != decoded.RouteManifestHash || bundle.PublishedAt != decoded.PublishedAt
                || !JsonSerializer.SerializeToUtf8Bytes(bundle.Policies).AsSpan().SequenceEqual(JsonSerializer.SerializeToUtf8Bytes(decoded.Policies)))
                throw new IamContractException("bundle_runtime_binding");
            reason = "valid"; return true;
        }
        catch (Exception ex) when (ex is JsonException or IamContractException or FormatException or ArgumentException
            or InvalidOperationException or KeyNotFoundException or NullReferenceException)
        { reason = "bundle_invalid"; return false; }
    }
}

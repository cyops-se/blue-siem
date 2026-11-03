using System.Text.Json;
using System.Text.Json.Serialization;

namespace BlueFwd.Service.Configuration;

public static class JsonDefaults
{
    public static readonly JsonSerializerOptions Options = Configure(new JsonSerializerOptions(JsonSerializerDefaults.Web)
    {
        WriteIndented = true,
    });

    public static JsonSerializerOptions Configure(JsonSerializerOptions options)
    {
        options.Converters.Add(new JsonStringEnumConverter());
        options.DefaultIgnoreCondition = JsonIgnoreCondition.Never;
        return options;
    }
}

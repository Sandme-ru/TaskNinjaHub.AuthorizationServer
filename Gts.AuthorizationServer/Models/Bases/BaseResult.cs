namespace Gts.AuthorizationServer.Models.Bases;

public class BaseResult
{
    public bool Success { get; set; }

    public object Result { get; set; } = null!;

    public string Error { get; set; } = null!;
}
namespace Gts.AuthorizationServer.Models.Bases;

public class BaseResult
{
    public bool success { get; set; }

    public object result { get; set; }

    public string error { get; set; }
}
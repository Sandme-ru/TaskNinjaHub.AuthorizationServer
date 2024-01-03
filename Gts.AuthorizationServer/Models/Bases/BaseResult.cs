namespace Gts.AuthorizationServer.Models.Bases;

/// <summary>
/// Class BaseResult.
/// </summary>
public class BaseResult
{
    /// <summary>
    /// Gets or sets a value indicating whether this <see cref="BaseResult"/> is success.
    /// </summary>
    /// <value><c>true</c> if success; otherwise, <c>false</c>.</value>
    public bool success { get; set; }

    /// <summary>
    /// Gets or sets the result.
    /// </summary>
    /// <value>The result.</value>
    public object result { get; set; }

    /// <summary>
    /// Gets or sets the error.
    /// </summary>
    /// <value>The error.</value>
    public string error { get; set; }
}
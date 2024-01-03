namespace Gts.AuthorizationServer.Helpers;

/// <summary>
/// Class AsyncEnumerableExtensions.
/// </summary>
public static class AsyncEnumerableExtensions
{
    /// <summary>
    /// Converts to listasync.
    /// </summary>
    /// <typeparam name="T"></typeparam>
    /// <param name="source">The source.</param>
    /// <returns>Task&lt;List&lt;T&gt;&gt;.</returns>
    /// <exception cref="System.ArgumentNullException">source</exception>
    public static Task<List<T>> ToListAsync<T>(this IAsyncEnumerable<T> source)
    {
        if (source == null)
        {
            throw new ArgumentNullException(nameof(source));
        }

        return ExecuteAsync();

        async Task<List<T>> ExecuteAsync()
        {
            var list = new List<T>();

            await foreach (var element in source)
            {
                list.Add(element);
            }

            return list;
        }
    }
}

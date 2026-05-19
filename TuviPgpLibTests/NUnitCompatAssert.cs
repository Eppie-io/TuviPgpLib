using NUnit.Framework;

namespace TuviPgpLibTests
{
    internal static class NUnitCompatAssert
    {
        public static TException Throws<TException>(Action action)
            where TException : Exception
        {
            return Assert.Throws<TException>((Action)action);
        }

        public static TException Throws<TException>(Action action, string message, params object?[]? args)
            where TException : Exception
        {
            return Assert.Throws<TException>((Action)action, message, args);
        }

        public static void DoesNotThrowAsync(Func<Task> action)
        {
            Assert.DoesNotThrowAsync((Func<Task>)action);
        }
    }
}

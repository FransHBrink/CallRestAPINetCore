using Microsoft.Extensions.Logging;
using System;
using System.Collections.Generic;
using System.Text;

namespace CallRestAPINetCore
{
    public class Logger
    {
        private readonly ILogger<Logger> _logger;

        public Logger(ILogger<Logger> logger)
        {
            _logger = logger;
        }

        public void LogWarningMessage(string name, string message)
        {
            _logger.LogWarning(20, message, name);
        }
    }
}
